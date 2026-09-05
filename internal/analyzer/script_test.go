package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
)

func TestLooksLikeShellScript(t *testing.T) {
	if !looksLikeShellScript("#!/bin/sh\nset -e\ncurl -fsSL https://example.com") {
		t.Fatalf("expected shell script detection to be true")
	}
	if looksLikeShellScript("<html><body>hello</body></html>") {
		t.Fatalf("expected html content to not be treated as shell script")
	}
}

func TestDomainAllowed(t *testing.T) {
	if domainAllowed("https://evil.test/install.sh", []string{"example.com"}) {
		t.Fatalf("expected domain to be blocked")
	}
	if !domainAllowed("https://sub.example.com/install.sh", []string{"example.com"}) {
		t.Fatalf("expected subdomain to be allowed")
	}
}

func TestAssertPublicIP(t *testing.T) {
	blocked := []string{"127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "172.16.0.5", "169.254.169.254", "100.64.0.1", "0.0.0.0"}
	for _, s := range blocked {
		if err := assertPublicIP(net.ParseIP(s)); err == nil {
			t.Errorf("expected %s to be blocked", s)
		}
	}
	if err := assertPublicIP(net.ParseIP("1.1.1.1")); err != nil {
		t.Errorf("expected 1.1.1.1 to be allowed, got %v", err)
	}
}

func TestHashContentUsesOriginalBytesNotLowercased(t *testing.T) {
	const body = "#!/bin/bash\nECHO HELLO\n"
	// fetchScript no longer lowercases content before hashing; verify hash is of raw bytes.
	sum := sha256.Sum256([]byte(body))
	want := hex.EncodeToString(sum[:])
	if hashContent(body) != want {
		t.Fatal("hashContent should hash original bytes")
	}
	if hashContent(strings.ToLower(body)) == want {
		// Different only when body has uppercase — ensure case matters.
		t.Fatal("expected lowercased body to produce a different hash")
	}
	// Patterns still match case-insensitively on original mixed-case body.
	findings := analyzeScriptBody("https://example.com/s.sh", body)
	// No suspicious patterns required; just ensure analyzer accepts original case.
	_ = findings
}

func TestAnalyzeScriptBodyDetectsSUIDPlanting(t *testing.T) {
	for _, body := range []string{
		"chmod 4755 /usr/local/bin/update-helper",
		"chmod 04755 /usr/bin/update-helper",
		"chmod u+s /bin/update-helper",
		"chmod a+s /usr/bin/update-helper",
	} {
		t.Run(body, func(t *testing.T) {
			findings := analyzeScriptBody("package.json:postinstall", body)
			if !hasReason(findings, "SUID_SGID_BIT_SET") {
				t.Fatalf("expected SUID_SGID_BIT_SET for %q, got %+v", body, findings)
			}
		})
	}
}

func TestAnalyzeScriptBodyIgnoresOrdinaryChmod(t *testing.T) {
	for _, body := range []string{
		"chmod 0755 /usr/local/bin/update-helper",
		"chmod 4755 ./test-fixture",
	} {
		t.Run(body, func(t *testing.T) {
			if findings := analyzeScriptBody("package.json:postinstall", body); hasReason(findings, "SUID_SGID_BIT_SET") {
				t.Fatalf("did not expect SUID finding for %q", body)
			}
		})
	}
}

func hasReason(findings []report.Finding, reason string) bool {
	for _, finding := range findings {
		if finding.ReasonCode == reason {
			return true
		}
	}
	return false
}

func TestFetchScriptBlocksLoopbackRedirect(t *testing.T) {
	loop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("secret"))
	}))
	defer loop.Close()

	client := newSafeScriptHTTPClient(nil)
	redirectTarget, err := http.NewRequest(http.MethodGet, loop.URL, nil)
	if err != nil {
		t.Fatalf("create redirect request: %v", err)
	}
	if err := client.CheckRedirect(redirectTarget, nil); !isSSRFBlockedError(err) {
		t.Fatalf("expected redirect destination to be blocked, got %v", err)
	}

	if _, _, _, err := fetchScript(client, loop.URL); !isSSRFBlockedError(err) {
		t.Fatalf("expected first-hop loopback fetch to be blocked, got %v", err)
	}
}

func TestScriptFetchedMarksTruncatedDigestAsPrefix(t *testing.T) {
	// A truncated body cannot have the upstream script's complete SHA-256.
	body := strings.Repeat("x", maxScriptBytes)
	evidence := scriptFetchEvidence(body, "text/plain", true)
	if !strings.HasPrefix(evidence, "sha256-prefix=") {
		t.Fatalf("expected truncated digest label, got %q", evidence)
	}
}
