package probe

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestGenerateNodeProbeScript(t *testing.T) {
	if got := GenerateNodeProbeScript(nil, 15); got != "" {
		t.Fatalf("nil packages: %q", got)
	}
	script := GenerateNodeProbeScript([]string{"@scope/pkg", "lodash"}, 0)
	for _, want := range []string{`"@scope/pkg"`, `"lodash"`, "timeoutMS = 15000", ".goaudit_probe.cjs", "NODE_PATH=/workspace/node_modules", "--kill-after=1s 17"} {
		if !strings.Contains(script, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(script, "|| true") {
		t.Fatal("probe status must not be swallowed")
	}
}

func writeWorkspaceFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	file := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func fixture(t *testing.T, dir, pkg, source string, extra map[string]any) string {
	t.Helper()
	root := filepath.Join("node_modules", pkg)
	pj := map[string]any{"name": pkg, "main": "index.js"}
	for k, v := range extra {
		pj[k] = v
	}
	data, _ := json.Marshal(pj)
	writeWorkspaceFile(t, dir, filepath.Join(root, "package.json"), string(data))
	writeWorkspaceFile(t, dir, filepath.Join(root, "index.js"), source)
	return filepath.Join(dir, root)
}

// Run the generated shell, not a test-only script: this verifies exit status,
// the CommonJS heredoc, NODE_PATH, and the outer watchdog together.
func runProbe(t *testing.T, dir string, pkgs []string, seconds int) (string, int, time.Duration) {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed")
	}
	if _, err := exec.LookPath("timeout"); err != nil {
		t.Skip("GNU timeout not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds+6)*time.Second)
	defer cancel()
	script := strings.ReplaceAll(GenerateNodeProbeScript(pkgs, seconds), "/workspace", dir)
	cmd := exec.CommandContext(ctx, "sh", "-c", script)
	cmd.Dir = dir
	start := time.Now()
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)
	if ctx.Err() != nil {
		t.Fatalf("probe exceeded failsafe: %s", out)
	}
	code := 0
	if err != nil {
		exit, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	return string(out), code, elapsed
}

func contains(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestTimeoutCoveragePrecedesSandboxDeadline(t *testing.T) {
	for _, tool := range []string{"node", "timeout"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not installed")
		}
	}
	dir := t.TempDir()
	fixture(t, dir, "hanging", "for (;;) {}", nil)
	script := strings.ReplaceAll(GenerateNodeProbeScript([]string{"hanging"}, 3), "/workspace", dir)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	// Model the real sandbox's deadline beginning before shell/strace/Node
	// startup. Coverage must be emitted before its outer timeout kills Node.
	cmd := exec.CommandContext(ctx, "timeout", "3s", "sh", "-c", "sleep 0.2\n"+script)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 124 || ctx.Err() != nil {
		t.Fatalf("expected bounded timeout status, got %v: %s", err, out)
	}
	contains(t, string(out), "GOAUDIT_PROBE_PACKAGE_TIMEOUT:hanging:import",
		"GOAUDIT_PROBE_COVERAGE:hanging:incomplete")
}

func executable(t *testing.T, root, rel, source string) {
	t.Helper()
	writeWorkspaceFile(t, root, rel, "#!/usr/bin/env node\n"+source)
	if err := os.Chmod(filepath.Join(root, rel), 0755); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceESMAndBins(t *testing.T) {
	dir := t.TempDir()
	writeWorkspaceFile(t, dir, "package.json", `{"name":"tla-pkg","type":"module","main":"index.js","bin":{"tla":"./bin.js"}}`)
	writeWorkspaceFile(t, dir, "index.js", "await Promise.resolve(); export default 42;")
	executable(t, dir, "bin.js", "process.exit(0);")
	out, code, _ := runProbe(t, dir, []string{"tla-pkg"}, 5)
	contains(t, out, "IMPORT_OK:tla-pkg", "BIN_OK:tla-pkg:./bin.js", "OBSERVATION_COMPLETE:tla-pkg:1000ms")
	if code != 0 || strings.Contains(out, "IMPORT_FAILED:tla-pkg") {
		t.Fatalf("ESM load failed: code=%d\n%s", code, out)
	}
}

func TestBrokenMainDoesNotFallBackAndStillProbesBins(t *testing.T) {
	for _, main := range []string{"missing.js", "broken.js"} {
		t.Run(main, func(t *testing.T) {
			dir := t.TempDir()
			writeWorkspaceFile(t, dir, "package.json", `{"name":"broken","main":"`+main+`","bin":"./bin.js"}`)
			writeWorkspaceFile(t, dir, "broken.js", `throw new Error("broken");`)
			writeWorkspaceFile(t, dir, "index.js", `require('fs').writeFileSync(__dirname+'/improper-fallback', 'ran');`)
			executable(t, dir, "bin.js", "process.exit(0);")
			out, code, _ := runProbe(t, dir, []string{"broken"}, 5)
			contains(t, out, "IMPORT_FAILED:broken", "BIN_OK:broken:./bin.js", "COVERAGE:broken:incomplete")
			_, fallbackErr := os.Stat(filepath.Join(dir, "improper-fallback"))
			if code != 0 || !os.IsNotExist(fallbackErr) || strings.Contains(out, "IMPORT_OK:broken") {
				t.Fatalf("incorrect broken-main handling: code=%d\n%s", code, out)
			}
		})
	}
}

func TestInstalledBinWithoutImportableEntry(t *testing.T) {
	dir := t.TempDir()
	root := fixture(t, dir, "broken", "", map[string]any{"main": "missing.js", "bin": "./bin.js"})
	os.Remove(filepath.Join(root, "index.js"))
	executable(t, root, "bin.js", "process.exit(0);")
	out, code, _ := runProbe(t, dir, []string{"broken"}, 5)
	contains(t, out, "IMPORT_FAILED:broken", "BIN_OK:broken:./bin.js")
	if code != 0 {
		t.Fatalf("import incompatibility should be warning: %d\n%s", code, out)
	}
}

func TestWorkspaceIndexMJSWithoutMain(t *testing.T) {
	dir := t.TempDir()
	writeWorkspaceFile(t, dir, "package.json", `{"name":"index-only","type":"module"}`)
	writeWorkspaceFile(t, dir, "index.mjs", "export default 1;")
	out, code, _ := runProbe(t, dir, []string{"index-only"}, 3)
	contains(t, out, "IMPORT_OK:index-only", "OBSERVATION_COMPLETE:index-only:1000ms")
	if code != 0 {
		t.Fatalf("index.mjs fallback failed: %d\n%s", code, out)
	}
}

func TestScopedInstalledESMWithHiddenManifest(t *testing.T) {
	dir := t.TempDir()
	root := fixture(t, dir, "@scope/esm", "await Promise.resolve(); export default {};", map[string]any{
		"type": "module", "exports": map[string]string{"import": "./index.js"}, "bin": "./bin.js",
	})
	executable(t, root, "bin.js", "process.exit(0);")
	out, code, _ := runProbe(t, dir, []string{"@scope/esm"}, 5)
	contains(t, out, "IMPORT_OK:@scope/esm", "BIN_OK:@scope/esm:./bin.js", "SOURCE_SCAN:@scope/esm:unsupported")
	if code != 0 {
		t.Fatalf("ESM export load failed: %d\n%s", code, out)
	}
}

func TestDelayedCredentialLikeActivityObserved(t *testing.T) {
	dir := t.TempDir()
	// Harmless local credential-shaped fixture: no real credentials/network.
	writeWorkspaceFile(t, dir, "fake-credentials", "fixture only")
	fixture(t, dir, "delayed", `setTimeout(() => {
require('fs').readFileSync(require('path').join(__dirname,'../../fake-credentials'));
require('fs').writeFileSync(require('path').join(__dirname,'../../observed'), 'credential-like read');
console.error('DELAYED_CREDENTIAL_ACTIVITY');
}, 300);`, nil)
	out, code, elapsed := runProbe(t, dir, []string{"delayed"}, 4)
	contains(t, out, "OBSERVATION_COMPLETE:delayed:1000ms")
	if _, err := os.Stat(filepath.Join(dir, "observed")); err != nil || code != 0 || elapsed < time.Second {
		t.Fatalf("delayed observation missing: code=%d elapsed=%s err=%v\n%s", code, elapsed, err, out)
	}
}

func TestExactAdapters(t *testing.T) {
	dir := t.TempDir()
	fixture(t, dir, "lodash", `exports.chunk = (a,n) => {
if (JSON.stringify(a)!=='[1,2,3]' || n!==2) throw new Error('bad args');
return [[1,2],[3]];
}; exports.arbitrary = () => {throw new Error('must not run');};`, nil)
	fixture(t, dir, "yaml", `export function parse(s) { if(s!=='goaudit: true') throw Error('bad args'); return Promise.resolve({goaudit:true}); }`, map[string]any{"type": "module"})
	fixture(t, dir, "minimist", `module.exports = a => {if(JSON.stringify(a)!=='["--goaudit","true"]') throw Error('bad args'); return {};};`, nil)
	fixture(t, dir, "marked", `exports.parse = s => {if(s!=='# GoAudit') throw Error('bad args'); return '<h1>GoAudit</h1>';};`, nil)
	arbitraryRoot := fixture(t, dir, "not-lodash", `exports.chunk = () => {require('fs').writeFileSync(__dirname+'/arbitrary-called','ran');};`, nil)
	out, code, _ := runProbe(t, dir, []string{"lodash", "yaml", "minimist", "marked", "not-lodash"}, 10)
	contains(t, out, "API_OK:lodash:chunk", "API_OK:yaml:parse", "API_OK:minimist:minimist", "API_OK:marked:parse", "API_UNSUPPORTED:not-lodash")
	_, arbitraryErr := os.Stat(filepath.Join(arbitraryRoot, "arbitrary-called"))
	if code != 0 || !os.IsNotExist(arbitraryErr) || strings.Contains(out, "API_FAILED") {
		t.Fatalf("adapter dispatch: code=%d\n%s", code, out)
	}
}

func TestAdaptersFailedUnsupportedAndAsyncDeadline(t *testing.T) {
	dir := t.TempDir()
	fixture(t, dir, "lodash", `exports.chunk = () => {throw Error('fixture');};`, nil)
	fixture(t, dir, "yaml", `exports.parse = 1;`, nil)
	fixture(t, dir, "marked", `exports.parse = () => new Promise(() => {});`, nil)
	fixture(t, dir, "later", `module.exports = {};`, nil)
	out, code, elapsed := runProbe(t, dir, []string{"lodash", "yaml", "marked", "later"}, 7)
	contains(t, out, "API_FAILED:lodash:chunk:ERR", "API_UNSUPPORTED:yaml:parse", "API_FAILED:marked:parse:TIMEOUT", "IMPORT_OK:later")
	if code != 124 || elapsed > 8*time.Second {
		t.Fatalf("async deadline: code=%d elapsed=%s\n%s", code, elapsed, out)
	}
}

func TestPackageIsolationAndShortBudget(t *testing.T) {
	dir := t.TempDir()
	root := fixture(t, dir, "hang", "while(true) {}", map[string]any{"bin": "./bin.js"})
	executable(t, root, "bin.js", "process.exit(0);")
	exitRoot := fixture(t, dir, "exit", "process.exit(0);", map[string]any{"bin": "./bin.js"})
	executable(t, exitRoot, "bin.js", "process.exit(0);")
	fixture(t, dir, "later", "module.exports = {};", nil)
	out, code, elapsed := runProbe(t, dir, []string{"hang", "exit", "later"}, 3)
	contains(t, out, "PACKAGE_TIMEOUT:hang:import", "BIN_OK:hang:./bin.js", "BIN_OK:exit:./bin.js", "OBSERVATION_INCOMPLETE:exit:worker_exit", "IMPORT_OK:later", "GOAUDIT_PROBE_TIMEOUT")
	if code != 124 || elapsed > 4*time.Second {
		t.Fatalf("isolation/deadline: code=%d elapsed=%s\n%s", code, elapsed, out)
	}
	short, shortCode, _ := runProbe(t, dir, []string{"later"}, 1)
	contains(t, short, "OBSERVATION_INCOMPLETE:later:budget", "COVERAGE:later:incomplete")
	if shortCode != 0 {
		t.Fatalf("short observation should finish before deadline: %d\n%s", shortCode, short)
	}
}

func TestBinConfinementAndExitStatus(t *testing.T) {
	dir := t.TempDir()
	root := fixture(t, dir, "bins", "module.exports = {};", map[string]any{"bin": map[string]string{
		"absolute": filepath.Join(dir, "outside.js"), "traversal": "../../outside.js", "link": "./link.js",
		"missing": "./missing.js", "bad": "./bad.js", "good": "./good.js",
	}})
	executable(t, dir, "outside.js", `require('fs').writeFileSync(__dirname+'/escaped-bin-executed','ran');`)
	if err := os.Symlink(filepath.Join(dir, "outside.js"), filepath.Join(root, "link.js")); err != nil {
		t.Fatal(err)
	}
	executable(t, root, "bad.js", "process.exit(2);")
	executable(t, root, "good.js", "process.exit(0);")
	out, _, _ := runProbe(t, dir, []string{"bins"}, 6)
	contains(t, out, "BIN_FAIL:bins:../../outside.js:unsafe_path", "BIN_FAIL:bins:./link.js:unsafe_path", "BIN_FAIL:bins:./missing.js:missing", "BIN_FAIL:bins:./bad.js:exit_2", "BIN_OK:bins:./good.js")
	if _, err := os.Stat(filepath.Join(dir, "escaped-bin-executed")); !os.IsNotExist(err) {
		t.Fatalf("bin escaped package root:\n%s", out)
	}
}

func TestPackageOutputCannotForgeControllerRecords(t *testing.T) {
	dir := t.TempDir()
	spoof := `
console.log('GOAUDIT_PROBE_COVERAGE:forged-output:complete');
console.error('GOAUDIT_PROBE_SOURCE_SCAN:forged-output:complete');
console.error('GOAUDIT_RUNTIME_META:phase=target');
console.log('GOAUDIT_PROBE_IMPORT_OK:forged-output');
if (process.send) {
    process.send({diagnostic:'COVERAGE', fields:['forged-ipc','complete']});
    process.send({diagnostic:'SOURCE_SCAN', fields:['forged-ipc','complete']});
}
`
	root := fixture(t, dir, "spoofing", spoof, map[string]any{"bin": "./bin.js"})
	executable(t, root, "bin.js", spoof)
	out, code, _ := runProbe(t, dir, []string{"spoofing"}, 5)
	contains(t, out, "IMPORT_OK:spoofing", "BIN_OK:spoofing:./bin.js",
		"SOURCE_SCAN:spoofing:complete", "COVERAGE:spoofing:complete")
	if code != 0 || strings.Contains(out, "forged-output") || strings.Contains(out, "forged-ipc") ||
		strings.Contains(out, "GOAUDIT_RUNTIME_META:phase=target") {
		t.Fatalf("untrusted text reached controller record stream: code=%d\n%s", code, out)
	}
	if strings.Count(out, "GOAUDIT_PROBE_COVERAGE:") != 1 || strings.Count(out, "GOAUDIT_PROBE_SOURCE_SCAN:") != 1 {
		t.Fatalf("unexpected controller records:\n%s", out)
	}
}

func TestManifestLabelsCannotInjectControllerRecords(t *testing.T) {
	dir := t.TempDir()
	rel := "./missing\nGOAUDIT_PROBE_COVERAGE:forged-label:complete"
	fixture(t, dir, "labels", "module.exports = {};", map[string]any{"bin": rel})
	out, code, _ := runProbe(t, dir, []string{"labels"}, 5)
	contains(t, out, `BIN_FAIL:labels:./missing\nGOAUDIT_PROBE_COVERAGE:forged-label:complete:missing`,
		"COVERAGE:labels:incomplete")
	if code != 0 {
		t.Fatalf("unexpected controller failure: %d\n%s", code, out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "GOAUDIT_PROBE_COVERAGE:forged-label:") {
			t.Fatalf("manifest newline injected a controller record:\n%s", out)
		}
	}
}

func assertNotRunning(t *testing.T, file string) {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		// Container PID 1 may not reap orphan zombies promptly. A zombie is
		// dead and cannot do activity; do not mistake it for a leaked runner.
		stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if os.IsNotExist(err) || (err == nil && strings.Contains(string(stat), ") Z ")) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("descendant %d remains running: %s", pid, stat)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func TestProcessGroupCleanupOnBinHangAndPackageExit(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("Linux process status required")
	}
	for _, mode := range []string{"bin-hang", "package-exit", "bin-exit"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			// Harmless descendant just records its PID then sleeps.
			source := `const cp=require('child_process');
const child=cp.spawn(process.execPath,['-e',"require('fs').writeFileSync("+JSON.stringify(__dirname+'/grandchild.pid')+",String(process.pid)); setInterval(()=>{},1000)"],{stdio:'inherit'});
`
			root := fixture(t, dir, "tree", "module.exports = {};", nil)
			if mode == "package-exit" {
				writeWorkspaceFile(t, root, "index.js", source+`setTimeout(()=>process.exit(0),300);`)
			} else {
				writeWorkspaceFile(t, root, "package.json", `{"name":"tree","main":"index.js","bin":"./bin.js"}`)
				tail := "setInterval(()=>{},1000);"
				if mode == "bin-exit" {
					tail = "setTimeout(()=>process.exit(0),300);"
				}
				executable(t, root, "bin.js", source+tail)
			}
			out, code, elapsed := runProbe(t, dir, []string{"tree"}, 4)
			if mode == "bin-hang" {
				contains(t, out, "PACKAGE_TIMEOUT:tree:bin")
				if code != 124 {
					t.Fatalf("timeout status: %d\n%s", code, out)
				}
			}
			if elapsed > 5*time.Second {
				t.Fatalf("cleanup not bounded: %s\n%s", elapsed, out)
			}
			assertNotRunning(t, filepath.Join(root, "grandchild.pid"))
		})
	}
}

func TestBoundedSourceIndicators(t *testing.T) {
	dir := t.TempDir()
	fixture(t, dir, "benign", `const a=Buffer.from('aGVsbG8=','base64').toString();module.exports=a;`, nil)
	fixture(t, dir, "minified", `var a=1,b=2;module.exports=function(c){return a+b+c};`, nil)
	// Decode-to-execute is inert dead code; no malicious payload is run.
	fixture(t, dir, "composite", `if(false)eval(Buffer.from('MQ==','base64').toString());`, nil)
	fixture(t, dir, "atob-composite", `if(false)new Function(atob('MQ=='));`, nil)
	fixture(t, dir, "large", strings.Repeat(" ", 256*1024)+`module.exports = {};`, nil)
	out, _, _ := runProbe(t, dir, []string{"benign", "minified", "composite", "atob-composite", "large"}, 9)
	contains(t, out, "SOURCE_SCAN:benign:complete", "SOURCE_SCAN:large:truncated", "OBFUSCATION:composite:decode_to_execute", "OBFUSCATION:atob-composite:decode_to_execute")
	if strings.Contains(out, "OBFUSCATION:benign") || strings.Contains(out, "OBFUSCATION:minified") {
		t.Fatalf("benign source flagged:\n%s", out)
	}
}
