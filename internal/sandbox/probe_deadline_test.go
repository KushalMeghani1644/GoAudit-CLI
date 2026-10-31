package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/probe"
)

func TestProbeDeadlineIncludesWrapperStartup(t *testing.T) {
	for _, tool := range []string{"node", "timeout", "bash", "date"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not installed")
		}
	}
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("package.json", `{"name":"hanging","main":"index.cjs"}`, 0o644)
	write("index.cjs", "for (;;) {}", 0o644)
	write("probe.sh", strings.ReplaceAll(probe.GenerateNodeProbeScript([]string{"hanging"}, 3), "/workspace", dir), 0o644)
	// Exercise the real generated watchdog and runuser command without requiring
	// root or tracing. Delay the strace wrapper beyond the 750ms reporting reserve.
	write("strace", `#!/bin/sh
shift 7
sleep 1
exec "$@"
`, 0o755)
	// Simulate an environment-clearing user switch: the timestamp must survive
	// via the explicit argument, not accidental environment inheritance.
	write("runuser", `#!/bin/sh
shift 3
unset GOAUDIT_PROBE_STARTED_MS
exec "$@"
`, 0o755)
	script := "SANDBOX_USER=unused\n" + tracedPhaseScript("probe", probePhaseCommand, "3s")
	script = strings.ReplaceAll(script, "/workspace", dir)
	script = strings.ReplaceAll(script, "/tmp/probe.sh", filepath.Join(dir, "probe.sh"))
	script = strings.ReplaceAll(script, "/tmp/goaudit-probe.strace", filepath.Join(dir, "probe.strace"))
	// tracedPhaseScript records status for its caller; propagate it here too.
	script += "\nexit \"$GOAUDIT_PROBE_RC\"\n"
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", script)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 124 || ctx.Err() != nil {
		t.Fatalf("expected bounded timeout status, got %v: %s", err, out)
	}
	for _, want := range []string{
		"GOAUDIT_PROBE_PACKAGE_TIMEOUT:hanging:import",
		"GOAUDIT_PROBE_COVERAGE:hanging:incomplete",
		"GOAUDIT_PROBE_EXIT:124",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("missing %q after delayed wrapper startup:\n%s", want, out)
		}
	}
}
