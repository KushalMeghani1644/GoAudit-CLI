package analyzer

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestExtractInstallSpecsStripsWrappers(t *testing.T) {
	cases := []string{
		"sudo npm install lodash",
		"env FOO=1 npm install lodash",
		"FOO=1 BAR=2 npm install lodash",
		"corepack npm install lodash",
	}
	for _, cmd := range cases {
		specs := extractInstallSpecs(cmd, "npm", []string{"install", "i"})
		if len(specs) != 1 || specs[0] != "lodash" {
			t.Fatalf("cmd %q: expected [lodash], got %#v", cmd, specs)
		}
	}
}

func TestSplitPackageSpecAndVersionSelect(t *testing.T) {
	name, ver := splitPackageSpec("lodash@4.17.21")
	if name != "lodash" || ver != "4.17.21" {
		t.Fatalf("unexpected split: %s %s", name, ver)
	}
	name, ver = splitPackageSpec("@scope/pkg@1.2.3")
	if name != "@scope/pkg" || ver != "1.2.3" {
		t.Fatalf("unexpected scoped split: %s %s", name, ver)
	}

	meta := &npmMetadata{
		DistTags: map[string]string{"latest": "2.0.0", "next": "3.0.0-rc"},
		Versions: map[string]struct {
			Scripts map[string]string `json:"scripts"`
		}{
			"1.0.0":    {},
			"2.0.0":    {},
			"3.0.0-rc": {},
		},
	}
	v, ev, approx := selectVersionToAnalyze(meta, "1.0.0")
	if v != "1.0.0" || !stringsContains(ev, "requested version") || approx {
		t.Fatalf("expected concrete version selection, got %s (%s) approx=%v", v, ev, approx)
	}
	v, ev, approx = selectVersionToAnalyze(meta, "")
	if v != "2.0.0" || approx {
		t.Fatalf("expected latest default for bare name, got %s (%s) approx=%v", v, ev, approx)
	}
	v, _, approx = selectVersionToAnalyze(meta, "next")
	if v != "3.0.0-rc" || approx {
		t.Fatalf("expected dist-tag resolution, got %s approx=%v", v, approx)
	}
	v, _, approx = selectVersionToAnalyze(meta, "^1.0.0")
	if v != "2.0.0" || !approx {
		t.Fatalf("expected range approximate fallback, got %s approx=%v", v, approx)
	}
	if !isConcreteVersion("1.2.3") || isConcreteVersion("^1.2.3") || isConcreteVersion("latest") {
		t.Fatal("concrete version checks failed")
	}
}

func TestExtractInstallSpecsQuotedAndWrappers(t *testing.T) {
	cases := []string{
		`npm install "lodash"`,
		`timeout 30s npm install lodash`,
		`nice -n 10 npm install lodash`,
		`sudo env FOO=1 npm install lodash`,
	}
	for _, cmd := range cases {
		specs := extractInstallSpecs(cmd, "npm", []string{"install", "i"})
		if len(specs) != 1 || specs[0] != "lodash" {
			t.Fatalf("cmd %q: expected [lodash], got %#v", cmd, specs)
		}
	}
}

func TestExtractInstallSpecsStopsAtShellSeparators(t *testing.T) {
	cases := []string{
		"npm install pkg || echo retry",
		"npm install pkg && echo done",
		"npm install pkg ; echo done",
		"npm install pkg | cat",
		// Separators without surrounding spaces must tokenize the same way.
		"npm install pkg||echo retry",
		"npm install pkg&&echo done",
		"npm install pkg;echo done",
		"npm install pkg|cat",
		// Quoted words adjacent to separators must be unquoted first.
		`npm install "pkg"&&echo done`,
		`npm install 'pkg'&&echo done`,
		`npm install "pkg" && echo done`,
	}
	for _, cmd := range cases {
		specs, partial := extractInstallSpecsFull(cmd, "npm", []string{"install", "i"})
		if len(specs) != 1 || specs[0] != "pkg" {
			t.Fatalf("cmd %q: expected [pkg], got %#v", cmd, specs)
		}
		if !partial {
			t.Fatalf("cmd %q: expected partial parse flag", cmd)
		}
	}

	// Separators inside a quoted token are literal, not clause boundaries.
	specs, partial := extractInstallSpecsFull(`npm install "pkg&&name"`, "npm", []string{"install", "i"})
	if len(specs) != 1 || specs[0] != "pkg&&name" {
		t.Fatalf("quoted separator: expected [pkg&&name], got %#v", specs)
	}
	if partial {
		t.Fatal("quoted separator: did not expect partial parse flag")
	}

	// Local-path arguments adjacent to separators keep their path form.
	specs, partial = extractInstallSpecsFull("npm install ./pkg&&echo done", "npm", []string{"install", "i"})
	if len(specs) != 1 || specs[0] != "./pkg" {
		t.Fatalf("local path: expected [./pkg], got %#v", specs)
	}
	if !partial {
		t.Fatal("local path: expected partial parse flag")
	}
}

func TestExtractInstallSpecsLineContinuations(t *testing.T) {
	cases := []string{
		"npm install \\\nlodash",
		"npm install \\\r\nlodash",
		"npm \\\n install lodash",
		"npm install \"lo\\\ndash\"",
	}
	for _, cmd := range cases {
		specs, partial := extractInstallSpecsFull(cmd, "npm", []string{"install", "i"})
		if len(specs) != 1 || specs[0] != "lodash" {
			t.Fatalf("cmd %q: expected [lodash], got %#v", cmd, specs)
		}
		if partial {
			t.Fatalf("cmd %q: did not expect partial parse flag", cmd)
		}
	}
}

func TestExtractInstallSpecsSudoUserFlag(t *testing.T) {
	cases := []string{
		"sudo -u user npm install lodash",
		"sudo -u user npm install --save lodash",
		"sudo --user=user npm install lodash",
		"sudo --user user npm install lodash",
		"sudo --group group npm install lodash",
		"sudo -E npm install lodash",
	}
	for _, cmd := range cases {
		specs := extractInstallSpecs(cmd, "npm", []string{"install", "i"})
		if len(specs) != 1 || specs[0] != "lodash" {
			t.Fatalf("cmd %q: expected [lodash], got %#v", cmd, specs)
		}
	}
}

func TestPackageParseIncompleteFinding(t *testing.T) {
	f, ok := packageParseIncompleteFinding(`sh -c "npm install $(echo lodash)"`)
	if !ok {
		t.Fatal("expected PACKAGE_PARSE_INCOMPLETE for substituted install")
	}
	if f.ReasonCode != "PACKAGE_PARSE_INCOMPLETE" {
		t.Fatalf("unexpected reason: %s", f.ReasonCode)
	}
	if _, ok := packageParseIncompleteFinding("npm install lodash"); ok {
		t.Fatal("did not expect incomplete finding for simple install")
	}
	// Unknown wrappers with package args must not pass silently.
	if _, ok := packageParseIncompleteFinding("unshare -r npm install lodash"); !ok {
		t.Fatal("expected PACKAGE_PARSE_INCOMPLETE for unknown wrapper with package args")
	}
	if _, ok := packageParseIncompleteFinding("npm install"); ok {
		t.Fatal("did not expect incomplete finding for bare npm install")
	}
}

func TestAnalyzeJSPackageManagersPartialParse(t *testing.T) {
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
				"4.17.21": {"scripts": {"postinstall": "node foo.js"}}
			}
		}`))
	}))
	defer srv.Close()

	old := npmRegistryBaseURL
	npmRegistryBaseURL = srv.URL
	defer func() { npmRegistryBaseURL = old }()

	cases := []string{
		"npm install lodash || echo retry",
		"npm install lodash | cat",
		"npm install lodash && npm install express",
	}
	for _, cmd := range cases {
		findings := AnalyzeJSPackageManagers(cmd)
		if findByReasonCode(findings, "NPM_LIFECYCLE_SCRIPT_METADATA") == nil {
			t.Fatalf("cmd %q: expected lifecycle finding for first segment, got %#v", cmd, findings)
		}
		f := findByReasonCode(findings, "PACKAGE_PARSE_INCOMPLETE")
		if f == nil {
			t.Fatalf("cmd %q: expected PACKAGE_PARSE_INCOMPLETE for partial parse, got %#v", cmd, findings)
		}
	}
	// A simple command must not be flagged as a partial parse.
	if findings := AnalyzeJSPackageManagers("npm install lodash"); findByReasonCode(findings, "PACKAGE_PARSE_INCOMPLETE") != nil {
		t.Fatalf("unexpected PACKAGE_PARSE_INCOMPLETE for simple install: %#v", findings)
	}
}

func TestSelectVersionToAnalyzeVPrefixed(t *testing.T) {
	meta := &npmMetadata{
		DistTags: map[string]string{"latest": "2.0.0"},
		Versions: map[string]struct {
			Scripts map[string]string `json:"scripts"`
		}{
			"1.2.3": {},
			"2.0.0": {},
		},
	}
	v, ev, approx := selectVersionToAnalyze(meta, "v1.2.3")
	if v != "1.2.3" || approx {
		t.Fatalf("expected v1.2.3 to resolve to 1.2.3, got %s approx=%v (%s)", v, approx, ev)
	}
	if !isConcreteVersion("v1.2.3") || !isConcreteVersion("V1.2.3") {
		t.Fatal("v-prefixed versions should be concrete")
	}
}

func TestStaticCoverageLimitFinding(t *testing.T) {
	// Force a tiny cap path by calling analyzeRegistryBackedSpecs with cap 1 and local specs
	// (no network). Local packages produce findings without registry HTTP.
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	for _, dir := range []string{dir1, dir2} {
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"p","version":"1.0.0"}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	findings := analyzeRegistryBackedSpecs([]string{dir1, dir2}, "npm", 1)
	if findByReasonCode(findings, "STATIC_COVERAGE_LIMIT") == nil {
		t.Fatalf("expected STATIC_COVERAGE_LIMIT, got %#v", findings)
	}
}

func stringsContains(s, sub string) bool {
	return strings.Contains(s, sub)
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

func TestRewriteSingleLocalPackageInstallExpandsHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".test-malicious-pkg")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	pkg := `{"name":"local-name","version":"1.0.0"}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0o644); err != nil {
		t.Fatal(err)
	}

	rewritten, projectPath, ok := RewriteSingleLocalPackageInstall("npm install ~/.test-malicious-pkg")
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

func TestSplitPackageSpecAliasResolvesTarget(t *testing.T) {
	name, ver := splitPackageSpec("alias@npm:lodash@4.17.21")
	if name != "lodash" || ver != "4.17.21" {
		t.Fatalf("unexpected alias resolution: %q %q", name, ver)
	}
	name, ver = splitPackageSpec("@scope/alias@npm:@scope/lodash@^1.0.0")
	if name != "@scope/lodash" || ver != "^1.0.0" {
		t.Fatalf("unexpected scoped alias resolution: %q %q", name, ver)
	}
}

func TestRewriteSingleLocalPackageInstallPreservesWrappers(t *testing.T) {
	dir := t.TempDir()
	pkg := `{"name":"local-name","version":"1.0.0"}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0o644); err != nil {
		t.Fatal(err)
	}

	command := "env NPM_CONFIG_REGISTRY=http://registry npm install " + dir
	rewritten, projectPath, ok := RewriteSingleLocalPackageInstall(command)
	if !ok {
		t.Fatal("expected rewrite to succeed")
	}
	want := "env NPM_CONFIG_REGISTRY=http://registry npm install ."
	if rewritten != want {
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

func TestExtractPackageNamesFromCommandResolvesAlias(t *testing.T) {
	names := ExtractPackageNamesFromCommand("npm install alias@npm:lodash@4.17.21")
	if len(names) != 1 || names[0] != "lodash" {
		t.Fatalf("expected alias target name, got %v", names)
	}
}
