package probe

import (
	"strings"
	"testing"
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
	if !strings.Contains(script, "/workspace/.goaudit_probe.js") {
		t.Fatal("expected probe to run from /workspace for node_modules resolution")
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
	if !strings.Contains(script, `require("/workspace");console.error("GOAUDIT_PROBE_IMPORT_OK:"+pkg);await _probeBins("/workspace");`) {
		t.Fatal("expected workspace import success path to probe declared bins")
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
	if !strings.Contains(script, `if(r<=0){clearTimeout(_timer);console.error("GOAUDIT_PROBE_TIMEOUT");process.exit(124);}`) {
		t.Fatal("expected shared deadline to emit GOAUDIT_PROBE_TIMEOUT before exit")
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

func TestProbeScriptFallbackResolvesPackageRoot(t *testing.T) {
	script := GenerateNodeProbeScript([]string{"lodash"}, 15)
	if !strings.Contains(script, `_path.dirname(require.resolve(pkg+"/package.json"))`) {
		t.Fatal("expected primary root resolution via pkg/package.json")
	}
	if !strings.Contains(script, `if(_fs.existsSync(_path.join(d,"package.json")))return d;`) {
		t.Fatal("expected fallback to walk up to directory containing package.json")
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
