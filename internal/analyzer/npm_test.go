package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
)

func TestExtractNPMPackageSpecs(t *testing.T) {
	specs := extractInstallSpecs("npm install @scope/pkg@1.2.3 lodash --save", "npm", []string{"install", "i"})
	if len(specs) != 2 {
		t.Fatalf("expected 2 specs, got %d", len(specs))
	}
	if specs[0] != "@scope/pkg@1.2.3" || specs[1] != "lodash" {
		t.Fatalf("unexpected specs: %#v", specs)
	}
}

func TestExtractPNPMSpecs(t *testing.T) {
	specs := extractInstallSpecs("pnpm add @scope/pkg@1.2.3 lodash", "pnpm", []string{"add", "install", "i"})
	if len(specs) != 2 {
		t.Fatalf("expected 2 specs, got %d", len(specs))
	}
}

func TestNormalizeNPMPackageName(t *testing.T) {
	if got := normalizeNPMPackageName("@scope/pkg@1.2.3"); got != "@scope/pkg" {
		t.Fatalf("unexpected scoped package normalize result: %s", got)
	}
	if got := normalizeNPMPackageName("lodash@4.17.21"); got != "lodash" {
		t.Fatalf("unexpected package normalize result: %s", got)
	}
}

func TestNonRegistryNpmSpec(t *testing.T) {
	if !isNonRegistryNpmSpec("git+https://github.com/foo/bar.git") {
		t.Fatalf("expected git URL to be non-registry")
	}
	if !isNonRegistryNpmSpec("./local-pkg") {
		t.Fatalf("expected local path to be non-registry")
	}
	if isNonRegistryNpmSpec("lodash") {
		t.Fatalf("expected registry package name to be registry-backed")
	}
}

func TestAnalyzeLocalPackageLifecycleContent(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	pkg := `{"name":"local-evil","version":"1.0.0","scripts":{"postinstall":"node scripts/setup.js"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0o644); err != nil {
		t.Fatal(err)
	}
	setup := `require("fs").readFileSync(process.env.HOME + "/.aws/credentials"); require("fs").appendFileSync(process.env.HOME + "/.ssh/authorized_keys", "x");`
	if err := os.WriteFile(filepath.Join(dir, "scripts", "setup.js"), []byte(setup), 0o644); err != nil {
		t.Fatal(err)
	}

	findings := analyzeRegistrySpec(nil, dir, "npm")
	if findByReasonCode(findings, "NPM_LIFECYCLE_CREDENTIAL_READ") == nil {
		t.Fatalf("expected local lifecycle credential finding, got %#v", findings)
	}
	if findByReasonCode(findings, "NPM_LIFECYCLE_PERSISTENCE_WRITE") == nil {
		t.Fatalf("expected local lifecycle persistence finding, got %#v", findings)
	}
}

func TestExtractPackageNamesFromCommandLocalPackage(t *testing.T) {
	dir := t.TempDir()
	pkg := `{"name":"local-name","version":"1.0.0"}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0o644); err != nil {
		t.Fatal(err)
	}

	got := ExtractPackageNamesFromCommand("npm install " + dir)
	if len(got) != 1 || got[0] != "local-name" {
		t.Fatalf("expected local package name, got %#v", got)
	}
}

func TestHasLocalPackageInstall(t *testing.T) {
	if !HasLocalPackageInstall("npm install ./local-pkg") {
		t.Fatal("expected local npm install")
	}
	if HasLocalPackageInstall("npm install lodash") {
		t.Fatal("did not expect registry package to be local install")
	}
}

func TestRewriteSingleLocalPackageInstall(t *testing.T) {
	dir := t.TempDir()
	pkg := `{"name":"local-name","version":"1.0.0"}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0o644); err != nil {
		t.Fatal(err)
	}

	rewritten, projectPath, ok := RewriteSingleLocalPackageInstall("npm install " + dir)
	if !ok {
		t.Fatal("expected rewrite to succeed")
	}
	if rewritten != "npm install ." {
		t.Fatalf("unexpected rewritten command: %s", rewritten)
	}
	if projectPath != dir {
		t.Fatalf("unexpected project path: %s", projectPath)
	}
}

func findByReasonCode(findings []report.Finding, code string) *report.Finding {
	for i := range findings {
		if findings[i].ReasonCode == code {
			return &findings[i]
		}
	}
	return nil
}
