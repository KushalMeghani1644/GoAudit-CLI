package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
)

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
	client := &http.Client{Timeout: 12 * time.Second}

	var crawl func(url string, depth int)
	crawl = func(url string, depth int) {
		if depth > maxDepth {
			return
		}
		if _, seen := visited[url]; seen {
			return
		}
		visited[url] = struct{}{}
		if !domainAllowed(url, allowedDomains) {
			findings = append(findings, report.Finding{
				Severity:   report.SeverityWarning,
				Type:       "script",
				ReasonCode: "POLICY_BLOCKED_DOMAIN",
				Path:       url,
				Confidence: 75,
				Evidence:   "Remote script URL blocked by allowlist policy",
			})
			return
		}

		body, contentType, err := fetchScript(client, url)
		if err != nil {
			findings = append(findings, report.Finding{
				Severity:   report.SeverityWarning,
				Type:       "script",
				ReasonCode: "INCONCLUSIVE_REMOTE_FETCH",
				Path:       url,
				Confidence: 35,
				Evidence:   err.Error(),
			})
			return
		}

		hash := hashContent(body)
		findings = append(findings, report.Finding{
			Severity:   report.SeverityInfo,
			Type:       "script",
			ReasonCode: "SCRIPT_FETCHED",
			Path:       url,
			Confidence: 80,
			Evidence:   fmt.Sprintf("sha256=%s; content-type=%s", hash, contentType),
		})

		isLikelyShell := looksLikeShellScript(body)
		findings = append(findings, analyzeScriptBody(url, body)...)

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

func fetchScript(client *http.Client, url string) (string, string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "goaudit/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("fetch failed with status %d", resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, 1<<20)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return "", "", err
	}
	return strings.ToLower(string(raw)), strings.ToLower(resp.Header.Get("Content-Type")), nil
}

func hashContent(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
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
