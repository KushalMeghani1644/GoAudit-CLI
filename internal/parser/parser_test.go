package parser

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
)

func TestParseStreamDoesNotResolveUnknownHosts(t *testing.T) {
	var dnsCalls atomic.Int32
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			dnsCalls.Add(1)
			return nil, fmt.Errorf("DNS must not be used while parsing")
		},
	}
	t.Cleanup(func() { net.DefaultResolver = original })

	for _, tt := range []struct {
		ip      string
		connect string
	}{
		{"8.8.8.8", `connect(7, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("8.8.8.8")}, 16) = 0`},
		{"2001:4860:4860::8888", `connect(7, {sa_family=AF_INET6, sin6_port=htons(443), inet_pton(AF_INET6, "2001:4860:4860::8888", &sin6_addr)}, 28) = 0`},
	} {
		t.Run(tt.ip, func(t *testing.T) {
			logs := "GOAUDIT_RUNTIME_META:phase=target\n" + tt.connect + "\n" +
				`sendto(7, "secret", 6, MSG_NOSIGNAL, NULL, 0) = 6` + "\n"
			findings, _ := parseWithHealth(t, logs, ParseOptions{})
			for _, reason := range []string{"EXTERNAL_NETWORK", "DATA_EXFIL"} {
				f := findByReason(findings, reason)
				if f == nil {
					t.Fatalf("expected %s finding", reason)
				}
				if f.Host != tt.ip || f.IP != tt.ip || f.Port != 443 {
					t.Fatalf("expected raw IP and port in %s, got %+v", reason, f)
				}
			}
		})
	}
	if got := dnsCalls.Load(); got != 0 {
		t.Fatalf("parser made %d DNS calls, want none", got)
	}
}

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
