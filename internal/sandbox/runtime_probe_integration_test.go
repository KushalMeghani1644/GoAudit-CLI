//go:build integration

package sandbox_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/parser"
	"github.com/KushalMeghani1644/GoAudit-CLI/internal/probe"
	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
	"github.com/KushalMeghani1644/GoAudit-CLI/internal/sandbox"
)

// Exercise the warm ExecScan path directly: project/local fixture scans
// deliberately bypass CLI caching, so they cannot validate this execution path.
// Fixture source is written and imported only inside the sandbox.
func TestRuntimeProbeCachedSandbox(t *testing.T) {
	image := os.Getenv("GOAUDIT_TEST_NODE_IMAGE")
	if image == "" {
		t.Skip("set GOAUDIT_TEST_NODE_IMAGE to a prepared Node sandbox image")
	}
	for _, enabled := range []bool{false, true} {
		name := "default-off"
		if enabled {
			name = "opt-in"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			s, err := sandbox.NewSandbox(ctx, image, sandbox.SandboxOptions{NetworkEnabled: false})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Cleanup(context.Background(), false)
			if s.Runtime() != "runsc" {
				t.Fatalf("expected runsc, got %s", s.Runtime())
			}
			if _, err := s.EnsureImage(ctx); err != nil {
				t.Fatal(err)
			}
			if err := s.PrepareWarm(ctx, "npm", image, []string{"node", "npm", "strace"}, nil); err != nil {
				t.Fatal(err)
			}
			target := `cat > /workspace/package.json <<'MANIFEST'
{"name":"goaudit-cached-fixture","version":"1.0.0","main":"index.cjs"}
MANIFEST
cat > /workspace/index.cjs <<'SOURCE'
setTimeout(() => require("fs").readFileSync(require("path").join(require("os").homedir(), ".aws", "credentials")), 200);
SOURCE
`
			script := ""
			if enabled {
				script = probe.GenerateNodeProbeScript([]string{"goaudit-cached-fixture"}, 10)
			}
			stream, err := s.ExecScan(ctx, target, script, "npm", image, "", "30s", "10s")
			if err != nil {
				t.Fatal(err)
			}
			findings, health, err := parser.ParseStreamWithHealth(stream, report.NewReporter(true, false), parser.ParseOptions{ProbeExpected: enabled})
			if err != nil {
				t.Fatal(err)
			}
			if !health.Usable() || health.TargetExitCode != 0 {
				t.Fatalf("incomplete trace: %#v", health)
			}
			want := report.VerdictClean
			if enabled {
				want = report.VerdictMalicious
				found := false
				for _, f := range findings {
					if f.ReasonCode == "CREDENTIAL_READ" && strings.Contains(f.Evidence, "[runtime probe]") {
						found = true
					}
				}
				if !found {
					t.Fatalf("missing probe-phase credential evidence: %#v", findings)
				}
			} else if health.ProbePhaseObserved {
				t.Fatal("default-off executed a probe")
			}
			if got := report.Evaluate(findings, report.EvaluationOptions{SuppressExpectedBehavior: true}); got != want {
				t.Fatalf("expected %s, got %s: %#v", want, got, findings)
			}
		})
	}
}
