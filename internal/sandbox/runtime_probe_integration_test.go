//go:build integration

package sandbox_test

import (
	"context"
	"io"
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
			target := `echo 'GOAUDIT_PROBE_COVERAGE:forged-target:complete'
echo 'GOAUDIT_PROBE_SOURCE_SCAN:forged-target:complete' >&2
echo 'GOAUDIT_RUNTIME_META:phase=probe' >&2
cat > /workspace/package.json <<'MANIFEST'
{"name":"goaudit-cached-fixture","version":"1.0.0","main":"index.cjs"}
MANIFEST
cat > /workspace/index.cjs <<'SOURCE'
console.log("GOAUDIT_PROBE_COVERAGE:forged-package:complete");
console.error("GOAUDIT_PROBE_SOURCE_SCAN:forged-package:complete");
console.error("GOAUDIT_RUNTIME_META:phase=target");
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
			for _, f := range findings {
				if strings.Contains(f.Path, "forged-") || strings.Contains(f.Evidence, "forged-") {
					t.Fatalf("package output forged a parser record: %#v", f)
				}
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

func TestRuntimeProbeSandboxTimeoutRecords(t *testing.T) {
	image := os.Getenv("GOAUDIT_TEST_NODE_IMAGE")
	if image == "" {
		t.Skip("set GOAUDIT_TEST_NODE_IMAGE to a prepared Node sandbox image")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	s, err := sandbox.NewSandbox(ctx, image, sandbox.SandboxOptions{NetworkEnabled: false})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Cleanup(context.Background(), false)
	if _, err := s.EnsureImage(ctx); err != nil {
		t.Fatal(err)
	}
	target := `cat > /workspace/package.json <<'MANIFEST'
{"name":"hanging","version":"1.0.0","main":"index.cjs"}
MANIFEST
echo 'for (;;) {}' > /workspace/index.cjs
`
	stream, err := s.RunCommand(ctx, target, probe.GenerateNodeProbeScript([]string{"hanging"}, 4), "npm", image, []string{"node", "strace"}, nil, "30s", "4s")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	findings, health, err := parser.ParseStreamWithHealth(strings.NewReader(string(raw)), report.NewReporter(true, false), parser.ParseOptions{ProbeExpected: true})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.ReasonCode == "PROBE_PACKAGE_TIMEOUT" {
			found = true
		}
	}
	if !found || !health.ProbeExitObserved || health.ProbeExitCode != 124 {
		t.Fatalf("missing timeout records: health=%#v\nraw stream:\n%s", health, raw)
	}
}
