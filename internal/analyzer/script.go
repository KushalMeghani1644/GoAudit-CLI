package analyzer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
)

const maxScriptBytes = 1 << 20 // 1 MiB

var suspiciousScriptPatterns = []struct {
	code       string
	pattern    *regexp.Regexp
	severity   report.Severity
	confidence int
}{
	{"STAGED_DOWNLOADER", regexp.MustCompile(`(?i)(curl|wget)[^|;\n]*(\||;).*?(sh|bash)`), report.SeverityCritical, 90},
	{"SCRIPT_OBFUSCATION", regexp.MustCompile(`(?i)(base64\s+-d|eval\s+\$?\(|python\s+-c\s+["'].*exec\()`), report.SeverityWarning, 80},
	{"PERSISTENCE_WRITE", regexp.MustCompile(`(?i)(/etc/cron|crontab|\.bashrc|\.zshrc|/etc/profile|authorized_keys)`), report.SeverityCritical, 90},
	{"CREDENTIAL_READ", regexp.MustCompile(`(?i)(\.aws/credentials|id_rsa|\.kube/config|\.env|\.git-credentials|\.npmrc)`), report.SeverityCritical, 85},
	{"REVERSE_SHELL", regexp.MustCompile(`(?i)(/dev/tcp/|nc\s+-e|bash\s+-i)`), report.SeverityCritical, 95},
	{"SUID_SGID_BIT_SET", regexp.MustCompile(`(?i)\bchmod(?:\s+--?[^\s]+)*\s+(?:0?[2-7][0-7]{3}|(?:a|u|g|\+)[+,a-z]*s)\s+(?:/usr/(?:local/)?bin/|/(?:s?bin|etc)/)`), report.SeverityCritical, 90},
}

func AnalyzeRemoteScripts(seedURLs []string, maxDepth int) []report.Finding {
	return AnalyzeRemoteScriptsWithPolicy(seedURLs, maxDepth, nil)
}

func AnalyzeRemoteScriptsWithPolicy(seedURLs []string, maxDepth int, allowedDomains []string) []report.Finding {
	if len(seedURLs) == 0 || maxDepth < 1 {
		return nil
	}

	visited := make(map[string]struct{})
	var findings []report.Finding
	client := newSafeScriptHTTPClient(allowedDomains)

	var crawl func(rawURL string, depth int)
	crawl = func(rawURL string, depth int) {
		if depth > maxDepth {
			return
		}
		if _, seen := visited[rawURL]; seen {
			return
		}
		visited[rawURL] = struct{}{}
		if !domainAllowed(rawURL, allowedDomains) {
			findings = append(findings, report.Finding{
				Severity:   report.SeverityWarning,
				Type:       "script",
				ReasonCode: "POLICY_BLOCKED_DOMAIN",
				Path:       rawURL,
				Confidence: 75,
				Evidence:   "Remote script URL blocked by allowlist policy",
			})
			return
		}

		body, contentType, truncated, err := fetchScript(client, rawURL)
		if err != nil {
			reason := "INCONCLUSIVE_REMOTE_FETCH"
			severity := report.SeverityWarning
			confidence := 35
			if isSSRFBlockedError(err) {
				reason = "SSRF_BLOCKED_DESTINATION"
				severity = report.SeverityWarning
				confidence = 85
			}
			findings = append(findings, report.Finding{
				Severity:   severity,
				Type:       "script",
				ReasonCode: reason,
				Path:       rawURL,
				Confidence: confidence,
				Evidence:   err.Error(),
			})
			return
		}

		findings = append(findings, report.Finding{
			Severity:   report.SeverityInfo,
			Type:       "script",
			ReasonCode: "SCRIPT_FETCHED",
			Path:       rawURL,
			Confidence: 80,
			Evidence:   scriptFetchEvidence(body, contentType, truncated),
		})
		if truncated {
			findings = append(findings, report.Finding{
				Severity:   report.SeverityWarning,
				Type:       "script",
				ReasonCode: "SCRIPT_TRUNCATED",
				Path:       rawURL,
				Confidence: 70,
				Evidence:   fmt.Sprintf("Remote script truncated at %d bytes for analysis", maxScriptBytes),
			})
		}

		// Analyze case-insensitively without mutating the stored artifact bytes used for hashing.
		isLikelyShell := looksLikeShellScript(strings.ToLower(body))
		findings = append(findings, analyzeScriptBody(rawURL, body)...)

		if isLikelyShell {
			for _, child := range ExtractURLs(body) {
				crawl(child, depth+1)
			}
		}
	}

	for _, u := range seedURLs {
		crawl(u, 1)
	}
	return findings
}

type ssrfBlockedError struct {
	msg string
}

func (e *ssrfBlockedError) Error() string { return e.msg }

func isSSRFBlockedError(err error) bool {
	var blocked *ssrfBlockedError
	return errors.As(err, &blocked)
}

func newSafeScriptHTTPClient(allowedDomains []string) *http.Client {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	transport := &http.Transport{
		// Proxies would receive the request and could connect to a private target
		// after DialContext has only validated the proxy address.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, &ssrfBlockedError{msg: "invalid dial address: " + address}
			}
			if err := assertPublicHost(host); err != nil {
				return nil, err
			}
			// Re-resolve and dial each IP only if public.
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, ip := range ips {
				if err := assertPublicIP(ip.IP); err != nil {
					lastErr = err
					continue
				}
				addr := net.JoinHostPort(ip.IP.String(), port)
				conn, err := dialer.DialContext(ctx, network, addr)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr == nil {
				lastErr = &ssrfBlockedError{msg: "no safe addresses for host " + host}
			}
			return nil, lastErr
		},
		// Force re-check of redirect destinations against allowlist + public IP policy.
		// CheckRedirect cannot dial, so we only validate the next URL host policy here;
		// DialContext re-validates IPs for the eventual connection.
	}

	return &http.Client{
		Timeout:   12 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return &ssrfBlockedError{msg: "too many redirects while fetching remote script"}
			}
			if req.URL == nil {
				return &ssrfBlockedError{msg: "redirect missing URL"}
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return &ssrfBlockedError{msg: "redirect to non-http(s) scheme blocked"}
			}
			if !domainAllowed(req.URL.String(), allowedDomains) {
				return &ssrfBlockedError{msg: "redirect destination blocked by domain allowlist: " + req.URL.Hostname()}
			}
			// Block literal IP hosts that are not public before dial.
			host := req.URL.Hostname()
			if ip := net.ParseIP(host); ip != nil {
				if err := assertPublicIP(ip); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func assertPublicHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return &ssrfBlockedError{msg: "empty host blocked"}
	}
	// Block obvious local hostnames even before resolution.
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") || lower == "metadata.google.internal" {
		return &ssrfBlockedError{msg: "blocked host: " + host}
	}
	if ip := net.ParseIP(host); ip != nil {
		return assertPublicIP(ip)
	}
	return nil
}

func assertPublicIP(ip net.IP) error {
	if ip == nil {
		return &ssrfBlockedError{msg: "nil IP blocked"}
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return &ssrfBlockedError{msg: "blocked non-public IP: " + ip.String()}
	}
	// Cloud metadata / CGNAT edge cases.
	if ip4 := ip.To4(); ip4 != nil {
		// 169.254.0.0/16 link-local already covered; explicit metadata IP.
		if ip4[0] == 169 && ip4[1] == 254 {
			return &ssrfBlockedError{msg: "blocked link-local IP: " + ip.String()}
		}
		// 100.64.0.0/10 shared address space (CGNAT) — treat as non-public.
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return &ssrfBlockedError{msg: "blocked shared-address-space IP: " + ip.String()}
		}
		// 0.0.0.0/8
		if ip4[0] == 0 {
			return &ssrfBlockedError{msg: "blocked IP: " + ip.String()}
		}
	}
	return nil
}

func fetchScript(client *http.Client, rawURL string) (body string, contentType string, truncated bool, err error) {
	if err := assertPublicHost(mustHostname(rawURL)); err != nil {
		// Hostname may be a domain; IP check only applies to literal IPs.
		// Domain resolution is enforced in DialContext.
		if net.ParseIP(mustHostname(rawURL)) != nil {
			return "", "", false, err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", "", false, err
	}
	req.Header.Set("User-Agent", "goaudit/1.0")

	resp, err := client.Do(req)
	if err != nil {
		if isSSRFBlockedError(err) {
			return "", "", false, err
		}
		return "", "", false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", false, fmt.Errorf("fetch failed with status %d", resp.StatusCode)
	}

	// Read one extra byte to detect truncation without mutating content for hashing.
	limited := io.LimitReader(resp.Body, maxScriptBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return "", "", false, err
	}
	if len(raw) > maxScriptBytes {
		truncated = true
		raw = raw[:maxScriptBytes]
	}
	ct := resp.Header.Get("Content-Type")
	return string(raw), ct, truncated, nil
}

func mustHostname(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func hashContent(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func scriptFetchEvidence(body, contentType string, truncated bool) string {
	hashLabel := "sha256"
	if truncated {
		hashLabel = "sha256-prefix"
	}
	return fmt.Sprintf("%s=%s; content-type=%s", hashLabel, hashContent(body), contentType)
}

func looksLikeShellScript(body string) bool {
	return strings.Contains(body, "#!/bin/sh") ||
		strings.Contains(body, "#!/bin/bash") ||
		strings.Contains(body, "set -e") ||
		strings.Contains(body, "apt-get") ||
		strings.Contains(body, "curl ") ||
		strings.Contains(body, "wget ")
}

func analyzeScriptBody(url, body string) []report.Finding {
	// Patterns are already case-insensitive; keep original body for evidence fidelity.
	var findings []report.Finding
	for _, s := range suspiciousScriptPatterns {
		if s.pattern.MatchString(body) {
			findings = append(findings, report.Finding{
				Severity:   s.severity,
				Type:       "script",
				ReasonCode: s.code,
				Path:       url,
				Confidence: s.confidence,
				Evidence:   "Matched static script detection pattern",
			})
		}
	}
	return findings
}

func domainAllowed(rawURL string, allowedDomains []string) bool {
	if len(allowedDomains) == 0 {
		return true
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	for _, d := range allowedDomains {
		dd := strings.ToLower(strings.TrimSpace(d))
		if dd == "" {
			continue
		}
		if host == dd || strings.HasSuffix(host, "."+dd) {
			return true
		}
	}
	return false
}
