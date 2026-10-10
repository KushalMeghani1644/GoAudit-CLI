package parser

import (
	"strings"
	"testing"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
)

func TestProbeCoverageDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		code, payload string
		severity      report.Severity
	}{
		{"PROBE_API_OK", "lodash:chunk", report.SeverityInfo},
		{"PROBE_API_FAILED", "yaml:parse:ERR_API", report.SeverityWarning},
		{"PROBE_API_UNSUPPORTED", "unrecognized", report.SeverityInfo},
		{"PROBE_BIN_OK", "cli:bin.js", report.SeverityInfo},
		{"PROBE_BIN_FAIL", "cli:../outside:rejected", report.SeverityWarning},
		{"PROBE_OBSERVATION_COMPLETE", "lodash:1000ms", report.SeverityInfo},
		{"PROBE_OBSERVATION_INCOMPLETE", "slow:exit", report.SeverityWarning},
		{"PROBE_PACKAGE_TIMEOUT", "slow:import", report.SeverityWarning},
		{"PROBE_COVERAGE", "@scope/pkg:complete", report.SeverityInfo},
		{"PROBE_COVERAGE", "@scope/pkg:incomplete", report.SeverityWarning},
		{"PROBE_SOURCE_SCAN", "lodash:truncated", report.SeverityInfo},
	} {
		t.Run(tc.code+"/"+tc.payload, func(t *testing.T) {
			findings := parse(t, "GOAUDIT_RUNTIME_META:phase=probe\nGOAUDIT_"+tc.code+":"+tc.payload+"\n")
			f := findByReason(findings, tc.code)
			if f == nil || f.Path != tc.payload || f.Severity != tc.severity || f.Type != "runtime" {
				t.Fatalf("unexpected coverage diagnostic: %#v", f)
			}
			if !strings.Contains(f.Evidence, "[runtime probe]") {
				t.Fatalf("missing phase evidence: %#v", f)
			}
		})
	}
}

func TestProbeObfuscationIsNotMalwareProof(t *testing.T) {
	findings := parse(t, "GOAUDIT_RUNTIME_META:phase=probe\nGOAUDIT_PROBE_OBFUSCATION:pkg:base64_execute\n")
	f := findByReason(findings, "PROBE_OBFUSCATION")
	if f == nil || f.Type != "script" || f.Severity != report.SeverityWarning {
		t.Fatalf("unexpected source indicator: %#v", f)
	}
	if got := report.Evaluate(findings, report.EvaluationOptions{}); got != report.VerdictSuspicious {
		t.Fatalf("source indicator must be suspicious, not malicious: %s", got)
	}
}

func TestProbeDiagnosticsIgnoreMarkersInsideSyscalls(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=probe\nGOAUDIT_PROBE_COVERAGE:pkg:incomplete\n" +
		"123 write(2, \"GOAUDIT_PROBE_COVERAGE:pkg:incomplete\\n\", 38) = 38\n" +
		"123 write(2, \"GOAUDIT_PROBE_IMPORT_OK:pkg\\n\", 28) = 28\n"
	findings := parse(t, input)
	count := 0
	for _, f := range findings {
		if f.ReasonCode == "PROBE_IMPORT_OK" {
			t.Fatalf("parsed marker embedded in syscall: %#v", f)
		}
		if f.ReasonCode == "PROBE_COVERAGE" {
			count++
			if f.Path != "pkg:incomplete" || f.Severity != report.SeverityWarning {
				t.Fatalf("malformed coverage: %#v", f)
			}
		}
	}
	if count != 1 {
		t.Fatalf("expected one actual coverage record, got %d", count)
	}
}

func TestSyscallArgumentsCannotForgeRuntimePhaseOrExit(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		"123 execve(\"/bin/echo\", [\"echo\", \"GOAUDIT_RUNTIME_META:phase=probe\"], []) = 0\n" +
		"123 execve(\"/bin/echo\", [\"echo\", \"GOAUDIT_PROBE_EXIT:0\"], []) = 0\n" +
		"123 execve(\"/bin/echo\", [\"echo\", \"GOAUDIT_RUNTIME_ERROR:missing_tool:node\"], []) = 0\n" +
		"123 openat(AT_FDCWD, \"/home/node/.aws/credentials\", O_RDONLY) = 3\n" +
		"GOAUDIT_TARGET_EXIT:0\n"
	findings, health := parseWithHealth(t, input, ParseOptions{})
	if health.ProbePhaseObserved || health.ProbeExitObserved {
		t.Fatalf("syscall text forged probe health: %#v", health)
	}
	if f := findByReason(findings, "RUNTIME_MISSING_TOOL"); f != nil {
		t.Fatalf("syscall text forged wrapper error: %#v", f)
	}
	f := findByReason(findings, "CREDENTIAL_READ")
	if f == nil || !strings.Contains(f.Evidence, "[install]") || strings.Contains(f.Evidence, "[runtime probe]") {
		t.Fatalf("forged marker changed credential phase: %#v", f)
	}
}
