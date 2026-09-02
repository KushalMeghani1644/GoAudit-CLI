package probe

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestGenerateNodeProbeScriptEmpty(t *testing.T) {
	if got := GenerateNodeProbeScript(nil, 15); got != "" {
		t.Fatalf("expected empty for nil packages, got %q", got)
	}
}

func TestGenerateNodeProbeScriptSinglePackage(t *testing.T) {
	script := GenerateNodeProbeScript([]string{"lodash"}, 15)
	if !strings.Contains(script, `"lodash"`) {
		t.Fatal("expected lodash in probe script")
	}
	if !strings.Contains(script, "require(") {
		t.Fatal("expected require() call")
	}
	if !strings.Contains(script, "timeout 17") {
		t.Fatalf("expected timeout 17 (15+2), got: %s", script)
	}
	if !strings.Contains(script, "/workspace/.goaudit_probe.cjs") {
		t.Fatal("expected probe to run from /workspace as CommonJS for node_modules resolution")
	}
	if !strings.Contains(script, "NODE_PATH=/workspace/node_modules") {
		t.Fatal("expected NODE_PATH to include installed packages")
	}
	if !strings.Contains(script, "--help") {
		t.Fatal("expected bin --help probe")
	}
	if !strings.Contains(script, "GOAUDIT_PROBE_LIMITATION") {
		t.Fatal("expected probe limitation marker")
	}
}

func TestProbeScriptWorkspaceProbesBins(t *testing.T) {
	script := GenerateNodeProbeScript([]string{"lodash"}, 15)
	if !strings.Contains(script, `try{require("/workspace");loaded=true;}`) {
		t.Fatal("expected workspace probe to try require() first")
	}
	if !strings.Contains(script, `await import(_url.pathToFileURL(_path.resolve("/workspace",cands[i])).href)`) {
		t.Fatal("expected workspace probe to fall back to dynamic import() of the entry point")
	}
	if !strings.Contains(script, `try{await _probeBins("/workspace",pkg);}catch(e){}return true;`) {
		t.Fatal("expected workspace bins to be probed regardless of import success")
	}
}

func TestProbeScriptUsesAsyncSpawnWithSharedDeadline(t *testing.T) {
	script := GenerateNodeProbeScript([]string{"lodash"}, 15)
	if strings.Contains(script, "spawnSync") {
		t.Fatal("expected no spawnSync: it blocks the event loop per binary")
	}
	if !strings.Contains(script, `_cp.spawn(bin,args,{env:process.env,stdio:"ignore"})`) {
		t.Fatal("expected async spawn for bin probes")
	}
	if !strings.Contains(script, `var _deadline=Date.now()+15000;`) {
		t.Fatal("expected one shared deadline across all binary probes")
	}
	if !strings.Contains(script, `if(r<=0){clearTimeout(_timer);_killChildren();console.error("GOAUDIT_PROBE_TIMEOUT");process.exit(124);}`) {
		t.Fatal("expected shared deadline to kill children and emit GOAUDIT_PROBE_TIMEOUT before exit")
	}
}

func TestProbeScriptChecksBinExitStatus(t *testing.T) {
	script := GenerateNodeProbeScript([]string{"lodash"}, 15)
	if !strings.Contains(script, `resolve(signal===null&&code===0)`) {
		t.Fatal("expected bin probe success to require clean exit (no signal, code 0)")
	}
	if !strings.Contains(script, `child.on("error",function(){`) {
		t.Fatal("expected spawn errors to be reported as failures")
	}
}

func TestProbeScriptReportsMissingBinAsFailure(t *testing.T) {
	script := GenerateNodeProbeScript([]string{"lodash"}, 15)
	if !strings.Contains(script, `if(!_fs.existsSync(bin)){console.error("GOAUDIT_PROBE_BIN_FAIL:"+label+":"+rel+":missing");continue;}`) {
		t.Fatal("expected missing declared bin to emit GOAUDIT_PROBE_BIN_FAIL before continue")
	}
}

func TestProbeScriptFallbackResolvesPackageRoot(t *testing.T) {
	script := GenerateNodeProbeScript([]string{"lodash"}, 15)
	if !strings.Contains(script, `_path.dirname(require.resolve(pkg+"/package.json"))`) {
		t.Fatal("expected primary root resolution via pkg/package.json")
	}
	if !strings.Contains(script, `if(_fs.existsSync(_path.join(d,"package.json")))return d;`) {
		t.Fatal("expected fallback to walk up to directory containing package.json")
	}
}

func TestProbeScriptTracksAndKillsChildrenOnTimeout(t *testing.T) {
	script := GenerateNodeProbeScript([]string{"lodash"}, 15)
	if !strings.Contains(script, `var _children=[];function _killChildren(){`) {
		t.Fatal("expected active children to be tracked with a kill helper")
	}
	if !strings.Contains(script, `var _timer=setTimeout(function(){_killChildren();console.error("GOAUDIT_PROBE_TIMEOUT");process.exit(124)}`) {
		t.Fatal("expected outer timeout handler to kill active children before exiting")
	}
	if !strings.Contains(script, `clearTimeout(_timer);_killChildren();console.error("GOAUDIT_PROBE_TIMEOUT");`) {
		t.Fatal("expected shared-deadline handler to kill active children before exiting")
	}
	spawnIdx := strings.Index(script, `_cp.spawn(bin,args,{env:process.env,stdio:"ignore"})`)
	deadlineIdx := strings.Index(script, `var r=_remaining();`)
	if spawnIdx < 0 || deadlineIdx < 0 || deadlineIdx > spawnIdx {
		t.Fatal("expected the shared deadline to be checked before spawning a binary")
	}
	if !strings.Contains(script, `_children.push(child);`) {
		t.Fatal("expected spawned binaries to be registered for cleanup")
	}
	if !strings.Contains(script, `if(i>=0)_children.splice(i,1);`) {
		t.Fatal("expected finished binaries to be removed from the tracking list")
	}
}

func TestGenerateNodeProbeScriptScopedPackage(t *testing.T) {
	script := GenerateNodeProbeScript([]string{"@scope/pkg", "lodash"}, 10)
	if !strings.Contains(script, `"@scope/pkg"`) {
		t.Fatal("expected scoped package in probe script")
	}
	if !strings.Contains(script, `"lodash"`) {
		t.Fatal("expected lodash in probe script")
	}
	if !strings.Contains(script, "timeout 12") {
		t.Fatal("expected timeout 12 (10+2)")
	}
}

func TestGenerateNodeProbeScriptDefaultTimeout(t *testing.T) {
	script := GenerateNodeProbeScript([]string{"x"}, 0)
	if !strings.Contains(script, "15000") {
		t.Fatal("expected default 15s timeout in JS")
	}
}

// extractProbeJS pulls the raw Node script out of the generated bash snippet
// so tests can execute it directly against a temp workspace.
func extractProbeJS(t *testing.T, script string) string {
	t.Helper()
	const marker = ".goaudit_probe.cjs\n"
	start := strings.Index(script, marker)
	if start < 0 {
		t.Fatalf("expected heredoc target in script: %s", script)
	}
	start += len(marker)
	end := strings.LastIndex(script, "\nGOAUDIT_PROBE_EOF\n")
	if end < start {
		t.Fatalf("expected heredoc terminator in script: %s", script)
	}
	return script[start:end]
}

// runProbeScript rewrites /workspace to dir, runs the probe with node, and
// returns the combined output.
func runProbeScript(t *testing.T, script string, timeoutSec int, mutate func(string) string, dir string) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	js := extractProbeJS(t, script)
	if mutate != nil {
		js = mutate(js)
	}
	js = strings.ReplaceAll(js, "/workspace", dir)
	// .cjs so the probe stays CommonJS even in "type": "module" workspaces,
	// mirroring what the generated bash snippet does.
	probePath := filepath.Join(dir, ".goaudit_probe.cjs")
	if err := os.WriteFile(probePath, []byte(js), 0o644); err != nil {
		t.Fatalf("write probe script: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec+10)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, probePath)
	cmd.Dir = dir
	out, _ := cmd.CombinedOutput()
	return string(out)
}

func writeWorkspaceFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

// Regression: an ESM workspace using top-level await makes require() throw
// ERR_REQUIRE_ASYNC_MODULE; the probe must still load it via dynamic import()
// and probe its declared bins instead of only reporting an import failure.
func TestProbeWorkspaceESMTopLevelAwaitProbesBins(t *testing.T) {
	dir := t.TempDir()
	pkg := map[string]any{
		"name":    "tla-pkg",
		"version": "1.0.0",
		"type":    "module",
		"main":    "index.js",
		"bin":     map[string]string{"tla-bin": "./bin.js"},
	}
	pkgJSON, _ := json.Marshal(pkg)
	writeWorkspaceFile(t, dir, "package.json", string(pkgJSON)+"\n")
	writeWorkspaceFile(t, dir, "index.js", "await Promise.resolve();\nexport default 42;\n")
	writeWorkspaceFile(t, dir, "bin.js", "#!/usr/bin/env node\nprocess.exit(0);\n")
	if err := os.Chmod(filepath.Join(dir, "bin.js"), 0o755); err != nil {
		t.Fatalf("chmod bin: %v", err)
	}

	out := runProbeScript(t, GenerateNodeProbeScript([]string{"tla-pkg"}, 15), 15, nil, dir)

	if !strings.Contains(out, "GOAUDIT_PROBE_BIN_OK:tla-pkg:./bin.js") {
		t.Fatalf("expected declared bin to be probed despite top-level await, output:\n%s", out)
	}
	if strings.Contains(out, "GOAUDIT_PROBE_IMPORT_FAILED:tla-pkg") {
		t.Fatalf("expected workspace load via dynamic import() to succeed, output:\n%s", out)
	}
}

// Regression: when the probe exits via a timeout handler, spawned --help
// children must be terminated instead of left running.
func TestProbeTimeoutKillsActiveBinChild(t *testing.T) {
	dir := t.TempDir()
	pkg := map[string]any{
		"name":    "hang-pkg",
		"version": "1.0.0",
		"main":    "index.js",
		"bin":     map[string]string{"hang": "./bin.js"},
	}
	pkgJSON, _ := json.Marshal(pkg)
	writeWorkspaceFile(t, dir, "package.json", string(pkgJSON)+"\n")
	writeWorkspaceFile(t, dir, "index.js", "module.exports = {};\n")
	// The bin records its pid and hangs forever, so only cleanup on the
	// timeout path can terminate it.
	writeWorkspaceFile(t, dir, "bin.js", "#!/usr/bin/env node\nrequire(\"fs\").writeFileSync(__dirname+\"/child.pid\", String(process.pid));\nsetInterval(function(){},1000);\n")
	if err := os.Chmod(filepath.Join(dir, "bin.js"), 0o755); err != nil {
		t.Fatalf("chmod bin: %v", err)
	}

	// Keep the shared deadline at 5s but fire the outer timeout at 1s so the
	// outer handler runs while the bin child is still active.
	script := GenerateNodeProbeScript([]string{"hang-pkg"}, 5)
	mutate := func(js string) string {
		return strings.Replace(js, "process.exit(124)},5000);", "process.exit(124)},1000);", 1)
	}
	out := runProbeScript(t, script, 5, mutate, dir)

	if !strings.Contains(out, "GOAUDIT_PROBE_TIMEOUT") {
		t.Fatalf("expected probe to time out, output:\n%s", out)
	}
	pidPath := filepath.Join(dir, "child.pid")
	pidBytes, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatalf("bin child never recorded its pid, output:\n%s", out)
	}
	var pid int
	if err := json.Unmarshal(pidBytes, &pid); err != nil {
		t.Fatalf("parse child pid: %v", err)
	}
	// A killed child is reaped once its parent (the probe) exits; allow a
	// short window for that before declaring a leak.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := syscall.Kill(pid, syscall.Signal(0)); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("bin child %d still alive after probe timeout, output:\n%s", pid, out)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
