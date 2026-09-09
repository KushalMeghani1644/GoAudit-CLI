package parser

import (
	"strings"
	"testing"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
)

func TestParseStreamDetectsRuntimeMissingTool(t *testing.T) {
	rep := report.NewReporter(true, false)
	logs := "GOAUDIT_RUNTIME_ERROR:missing_tool:curl\n"
	findings, err := ParseStream(strings.NewReader(logs), rep, ParseOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].ReasonCode != "RUNTIME_MISSING_TOOL" {
		t.Fatalf("expected runtime missing tool reason, got %s", findings[0].ReasonCode)
	}
}

func TestParseStreamDetectsTargetExitFailure(t *testing.T) {
	rep := report.NewReporter(true, false)
	logs := "GOAUDIT_TARGET_EXIT:127\n"
	findings, err := ParseStream(strings.NewReader(logs), rep, ParseOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].ReasonCode != "TARGET_COMMAND_NOT_FOUND" {
		t.Fatalf("expected target command not found reason, got %s", findings[0].ReasonCode)
	}
}

func parseWithHealth(t *testing.T, logs string, opts ParseOptions) ([]report.Finding, TraceHealth) {
	t.Helper()
	rep := report.NewReporter(true, false)
	findings, health, err := ParseStreamWithHealth(strings.NewReader(logs), rep, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings, health
}

func TestParseStreamTraceHealthHealthy(t *testing.T) {
	_, health := parseWithHealth(t, "GOAUDIT_RUNTIME_META:phase=target\ngetpid() = 42\nGOAUDIT_TARGET_EXIT:0\n", ParseOptions{})
	if !health.Usable() {
		t.Fatalf("expected usable trace health: %#v", health)
	}
}

func TestParseStreamTraceHealthMissingTargetPhase(t *testing.T) {
	_, health := parseWithHealth(t, "getpid() = 42\nGOAUDIT_TARGET_EXIT:0\n", ParseOptions{})
	if health.Usable() {
		t.Fatalf("expected unusable trace health without target phase: %#v", health)
	}
}

func TestParseStreamTraceHealthMissingTargetExit(t *testing.T) {
	_, health := parseWithHealth(t, "GOAUDIT_RUNTIME_META:phase=target\ngetpid() = 42\n", ParseOptions{})
	if health.Usable() {
		t.Fatalf("expected unusable trace health without explicit target exit: %#v", health)
	}
}

func TestParseStreamTraceHealthExpectedProbeMissing(t *testing.T) {
	_, health := parseWithHealth(t, "GOAUDIT_RUNTIME_META:phase=target\ngetpid() = 42\nGOAUDIT_TARGET_EXIT:0\n", ParseOptions{ProbeExpected: true})
	if health.Usable() {
		t.Fatalf("expected unusable trace health without probe phase: %#v", health)
	}
}

func TestParseStreamProbeFindingAnnotated(t *testing.T) {
	logs := "GOAUDIT_RUNTIME_META:phase=target\n" +
		"getpid() = 42\n" +
		"GOAUDIT_TARGET_EXIT:0\n" +
		"GOAUDIT_RUNTIME_META:phase=probe\n" +
		`openat(AT_FDCWD, "/root/.aws/credentials", O_RDONLY) = 3` + "\n" +
		"GOAUDIT_PROBE_EXIT:0\n"
	findings, _ := parseWithHealth(t, logs, ParseOptions{ProbeExpected: true})

	var credentialFinding *report.Finding
	for i := range findings {
		if findings[i].ReasonCode == "CREDENTIAL_READ" {
			credentialFinding = &findings[i]
			break
		}
	}
	if credentialFinding == nil {
		t.Fatal("expected CREDENTIAL_READ finding")
	}
	if !strings.Contains(credentialFinding.Evidence, "[runtime probe]") {
		t.Fatalf("expected probe annotation, got %q", credentialFinding.Evidence)
	}
}

func TestParseStreamDetectsProbeTimeout(t *testing.T) {
	findings, health := parseWithHealth(t, "GOAUDIT_RUNTIME_META:phase=probe\nGOAUDIT_PROBE_EXIT:124\n", ParseOptions{ProbeExpected: true})
	if findByReason(findings, "PROBE_COMMAND_TIMEOUT") == nil {
		t.Fatal("expected PROBE_COMMAND_TIMEOUT for probe exit 124")
	}
	if health.ProbeExitCode != 124 || !health.ProbeExitObserved {
		t.Fatalf("expected probe exit health, got %#v", health)
	}
}

func TestParseStreamTraceHealthExpectedProbeNeedsSyscallAndExit(t *testing.T) {
	_, health := parseWithHealth(t, "GOAUDIT_RUNTIME_META:phase=target\ngetpid() = 42\nGOAUDIT_TARGET_EXIT:0\nGOAUDIT_RUNTIME_META:phase=probe\n", ParseOptions{ProbeExpected: true})
	if health.Usable() {
		t.Fatalf("expected unusable trace health without probe syscall and exit: %#v", health)
	}
}
