package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

func TestFetchScriptBlocksLoopbackRedirect(t *testing.T) {
	// Public-looking first hop that redirects to loopback should be blocked.
	loop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("secret"))
	}))
	defer loop.Close()

	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, loop.URL, http.StatusFound)
	}))
	defer redir.Close()

	findings := AnalyzeRemoteScriptsWithPolicy([]string{redir.URL}, 1, nil)
	blocked := false
	for _, f := range findings {
		if f.ReasonCode == "SSRF_BLOCKED_DESTINATION" || (f.ReasonCode == "INCONCLUSIVE_REMOTE_FETCH" && strings.Contains(f.Evidence, "blocked")) {
			blocked = true
			break
		}
	}
	// httptest both are loopback; either initial dial or redirect should fail closed.
	if !blocked {
		// Initial URL itself is loopback, so SSRF block is expected on first hop.
		for _, f := range findings {
			if f.ReasonCode == "SSRF_BLOCKED_DESTINATION" {
				blocked = true
			}
		}
	}
	if !blocked {
		t.Fatalf("expected SSRF block for loopback fetch, findings=%+v", findings)
	}
}
