package report

import (
	"encoding/json"
	"strings"
	"testing"
)

var defaultOpts = EvaluationOptions{}

func TestEvaluateMaliciousForCredentialRead(t *testing.T) {
	verdict := Evaluate([]Finding{
		{Severity: SeverityCritical, ReasonCode: "CREDENTIAL_READ"},
	}, defaultOpts)
	if verdict != VerdictMalicious {
		t.Fatalf("expected malicious verdict, got %s", verdict)
	}
}

func TestEvaluateSuspiciousForCurlPipeShellOnly(t *testing.T) {
	verdict := Evaluate([]Finding{
		{Severity: SeverityWarning, ReasonCode: "CURL_PIPE_SHELL"},
	}, defaultOpts)
	if verdict != VerdictSuspicious {
		t.Fatalf("expected suspicious verdict, got %s", verdict)
	}
}

func TestEvaluateInconclusiveForRuntimeIssue(t *testing.T) {
	verdict := Evaluate([]Finding{
		{Severity: SeverityWarning, ReasonCode: "RUNTIME_MISSING_TOOL"},
	}, defaultOpts)
	if verdict != VerdictInconclusive {
		t.Fatalf("expected inconclusive verdict, got %s", verdict)
	}
}

func TestEvaluateInconclusiveForRuntimeTraceUnavailable(t *testing.T) {
	verdict := Evaluate([]Finding{
		{Severity: SeverityWarning, ReasonCode: "RUNTIME_TRACE_UNAVAILABLE"},
	}, defaultOpts)
	if verdict != VerdictInconclusive {
		t.Fatalf("expected inconclusive verdict, got %s", verdict)
	}
}

func TestEvaluateInconclusiveForTargetFailure(t *testing.T) {
	verdict := Evaluate([]Finding{
		{Severity: SeverityWarning, ReasonCode: "TARGET_COMMAND_NOT_FOUND"},
	}, defaultOpts)
	if verdict != VerdictInconclusive {
		t.Fatalf("expected inconclusive verdict, got %s", verdict)
	}
}

func TestEvaluateSuppressExpectedBehavior(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityWarning, ReasonCode: "NPM_LIFECYCLE_SCRIPTS"},
		{Severity: SeverityInfo, ReasonCode: "EXTERNAL_NETWORK_REGISTRY"},
	}
	verdict := Evaluate(findings, EvaluationOptions{SuppressExpectedBehavior: true})
	if verdict != VerdictClean {
		t.Fatalf("expected clean verdict with suppression, got %s", verdict)
	}
}

func TestEvaluateEnvTheftIsMalicious(t *testing.T) {
	verdict := Evaluate([]Finding{
		{Severity: SeverityCritical, ReasonCode: "ENV_THEFT"},
	}, defaultOpts)
	if verdict != VerdictMalicious {
		t.Fatalf("expected malicious verdict for ENV_THEFT, got %s", verdict)
	}
}

func TestEvaluateDataExfilIsMalicious(t *testing.T) {
	verdict := Evaluate([]Finding{
		{Severity: SeverityCritical, ReasonCode: "DATA_EXFIL"},
	}, defaultOpts)
	if verdict != VerdictMalicious {
		t.Fatalf("expected malicious verdict for DATA_EXFIL, got %s", verdict)
	}
}

func TestEvaluatePrivilegeEscalationIsMalicious(t *testing.T) {
	verdict := Evaluate([]Finding{
		{Severity: SeverityCritical, ReasonCode: "PRIVILEGE_ESCALATION"},
	}, defaultOpts)
	if verdict != VerdictMalicious {
		t.Fatalf("expected malicious verdict for PRIVILEGE_ESCALATION, got %s", verdict)
	}
}

func TestEvaluatePrivilegeEscalationAttemptIsSuspicious(t *testing.T) {
	verdict := Evaluate([]Finding{
		{Severity: SeverityWarning, ReasonCode: "PRIVILEGE_ESCALATION_ATTEMPT"},
	}, defaultOpts)
	if verdict != VerdictSuspicious {
		t.Fatalf("expected suspicious verdict for PRIVILEGE_ESCALATION_ATTEMPT, got %s", verdict)
	}
}

func TestPrivilegedKernelOperationVerdicts(t *testing.T) {
	t.Run("failed attempt is suspicious", func(t *testing.T) {
		verdict := Evaluate([]Finding{{
			Severity:   SeverityWarning,
			ReasonCode: "PRIVILEGED_KERNEL_OPERATION_ATTEMPT",
		}}, defaultOpts)
		if verdict != VerdictSuspicious {
			t.Fatalf("expected suspicious verdict for failed kernel operation, got %s", verdict)
		}
	})

	t.Run("successful operation is malicious", func(t *testing.T) {
		verdict := Evaluate([]Finding{{
			Severity:   SeverityCritical,
			ReasonCode: "PRIVILEGED_KERNEL_OPERATION",
		}}, defaultOpts)
		if verdict != VerdictMalicious {
			t.Fatalf("expected malicious verdict for successful kernel operation, got %s", verdict)
		}
	})
}

func TestFailedPrivilegeOperationsShareSuspiciousCeiling(t *testing.T) {
	verdict := Evaluate([]Finding{
		{Severity: SeverityWarning, ReasonCode: "PRIVILEGE_ESCALATION_ATTEMPT"},
		{Severity: SeverityWarning, ReasonCode: "MOUNT_OPERATION_ATTEMPT"},
		{Severity: SeverityWarning, ReasonCode: "PRIVILEGED_KERNEL_OPERATION_ATTEMPT"},
		{Severity: SeverityWarning, ReasonCode: "ACCOUNT_FILE_ACCESS"},
	}, defaultOpts)
	if verdict != VerdictSuspicious {
		t.Fatalf("expected failed privilege operations to remain suspicious, got %s", verdict)
	}
}

func TestEvaluateFailedAccountFileAccessNotMalicious(t *testing.T) {
	// Denied shadow access alone must not force MALICIOUS (scanner false positive path).
	verdict := Evaluate([]Finding{
		{Severity: SeverityWarning, ReasonCode: "ACCOUNT_FILE_ACCESS", Path: "/etc/shadow"},
	}, defaultOpts)
	if verdict == VerdictMalicious {
		t.Fatalf("expected non-malicious verdict for failed ACCOUNT_FILE_ACCESS, got %s", verdict)
	}
	if verdict != VerdictSuspicious {
		t.Fatalf("expected suspicious verdict for failed ACCOUNT_FILE_ACCESS, got %s", verdict)
	}
}

func TestEvaluateFailedMountNotMalicious(t *testing.T) {
	verdict := Evaluate([]Finding{
		{Severity: SeverityWarning, ReasonCode: "MOUNT_OPERATION_ATTEMPT"},
	}, defaultOpts)
	if verdict == VerdictMalicious {
		t.Fatalf("expected non-malicious verdict for failed mount, got %s", verdict)
	}
	if verdict != VerdictSuspicious {
		t.Fatalf("expected suspicious verdict for failed mount, got %s", verdict)
	}
}

func TestEvaluateSuccessfulShadowAccessIsMalicious(t *testing.T) {
	verdict := Evaluate([]Finding{
		{Severity: SeverityCritical, ReasonCode: "ACCOUNT_FILE_ACCESS", Path: "/etc/shadow"},
	}, defaultOpts)
	if verdict != VerdictMalicious {
		t.Fatalf("expected malicious verdict for critical ACCOUNT_FILE_ACCESS, got %s", verdict)
	}
}

func TestEvaluatePasswdReadOnlyNotMalicious(t *testing.T) {
	// Simulates a clean non-root scan that only has registry traffic + no account findings.
	// (passwd reads are suppressed in the parser; ensure leftover info wouldn't hard-fail.)
	verdict := Evaluate([]Finding{
		{Severity: SeverityInfo, ReasonCode: "EXTERNAL_NETWORK_REGISTRY"},
	}, defaultOpts)
	if verdict == VerdictMalicious {
		t.Fatalf("expected non-malicious clean install-like findings, got %s", verdict)
	}
}

func TestEvaluatePrivilegeEscalationAttemptWithMaliciousFinding(t *testing.T) {
	verdict := Evaluate([]Finding{
		{Severity: SeverityWarning, ReasonCode: "PRIVILEGE_ESCALATION_ATTEMPT"},
		{Severity: SeverityCritical, ReasonCode: "CREDENTIAL_READ"},
	}, defaultOpts)
	if verdict != VerdictMalicious {
		t.Fatalf("expected malicious verdict when attempt combines with hard malicious finding, got %s", verdict)
	}
}

func TestEvaluateDoesNotStackWarningsIntoMaliciousVerdict(t *testing.T) {
	verdict := Evaluate([]Finding{
		{Severity: SeverityWarning, ReasonCode: "STAGED_DOWNLOADER"},
		{Severity: SeverityWarning, ReasonCode: "CURL_PIPE_SHELL"},
	}, defaultOpts)
	if verdict != VerdictSuspicious {
		t.Fatalf("expected transparent warning signals to remain suspicious, got %s", verdict)
	}
}

func TestBuildSignalsReportsRawObservations(t *testing.T) {
	signals := BuildSignals([]Finding{
		{Severity: SeverityCritical, Type: "fs_read", ReasonCode: "CREDENTIAL_READ", Path: "/home/node/.npmrc"},
		{Severity: SeverityWarning, Type: "network", ReasonCode: "EXTERNAL_NETWORK", Host: "example.com", IP: "203.0.113.7", Port: 443},
		{Severity: SeverityWarning, Type: "npm", ReasonCode: "NPM_RECENT_PACKAGE", Path: "example"},
	})
	data, err := json.Marshal(Report{Verdict: VerdictMalicious, Signals: signals})
	if err != nil {
		t.Fatal(err)
	}
	output := string(data)
	for _, expected := range []string{
		`"category":"credential-access"`,
		`"kind":"file-read"`,
		`"path":"/home/node/.npmrc"`,
		`"category":"network-exfil"`,
		`"kind":"network-connection"`,
		`"host":"example.com"`,
		`"category":"suspicious-registry"`,
		`"kind":"registry-metadata-flag"`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("expected %s in report: %s", expected, output)
		}
	}
	if strings.Contains(strings.ToLower(output), "confidence") || strings.Contains(output, `"findings"`) {
		t.Fatalf("legacy scoring fields leaked into CI schema: %s", output)
	}
}
