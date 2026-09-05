package report

import "testing"

var defaultOpts = EvaluationOptions{}

func TestEvaluateMaliciousForCredentialRead(t *testing.T) {
	verdict, confidence := Evaluate([]Finding{
		{Severity: SeverityCritical, ReasonCode: "CREDENTIAL_READ"},
	}, defaultOpts)
	if verdict != VerdictMalicious {
		t.Fatalf("expected malicious verdict, got %s", verdict)
	}
	if confidence < 80 {
		t.Fatalf("expected high confidence, got %d", confidence)
	}
}

func TestEvaluateSuspiciousForCurlPipeShellOnly(t *testing.T) {
	verdict, _ := Evaluate([]Finding{
		{Severity: SeverityWarning, ReasonCode: "CURL_PIPE_SHELL"},
	}, defaultOpts)
	if verdict != VerdictSuspicious {
		t.Fatalf("expected suspicious verdict, got %s", verdict)
	}
}

func TestEvaluateInconclusiveForRuntimeIssue(t *testing.T) {
	verdict, _ := Evaluate([]Finding{
		{Severity: SeverityWarning, ReasonCode: "RUNTIME_MISSING_TOOL"},
	}, defaultOpts)
	if verdict != VerdictInconclusive {
		t.Fatalf("expected inconclusive verdict, got %s", verdict)
	}
}

func TestEvaluateInconclusiveForRuntimeTraceUnavailable(t *testing.T) {
	verdict, _ := Evaluate([]Finding{
		{Severity: SeverityWarning, ReasonCode: "RUNTIME_TRACE_UNAVAILABLE"},
	}, defaultOpts)
	if verdict != VerdictInconclusive {
		t.Fatalf("expected inconclusive verdict, got %s", verdict)
	}
}

func TestEvaluateInconclusiveForTargetFailure(t *testing.T) {
	verdict, _ := Evaluate([]Finding{
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
	verdict, _ := Evaluate(findings, EvaluationOptions{SuppressExpectedBehavior: true})
	if verdict != VerdictClean {
		t.Fatalf("expected clean verdict with suppression, got %s", verdict)
	}
}

func TestEvaluateEnvTheftIsMalicious(t *testing.T) {
	verdict, _ := Evaluate([]Finding{
		{Severity: SeverityCritical, ReasonCode: "ENV_THEFT"},
	}, defaultOpts)
	if verdict != VerdictMalicious {
		t.Fatalf("expected malicious verdict for ENV_THEFT, got %s", verdict)
	}
}

func TestEvaluateDataExfilIsMalicious(t *testing.T) {
	verdict, _ := Evaluate([]Finding{
		{Severity: SeverityCritical, ReasonCode: "DATA_EXFIL"},
	}, defaultOpts)
	if verdict != VerdictMalicious {
		t.Fatalf("expected malicious verdict for DATA_EXFIL, got %s", verdict)
	}
}

func TestEvaluatePrivilegeEscalationIsMalicious(t *testing.T) {
	verdict, _ := Evaluate([]Finding{
		{Severity: SeverityCritical, ReasonCode: "PRIVILEGE_ESCALATION"},
	}, defaultOpts)
	if verdict != VerdictMalicious {
		t.Fatalf("expected malicious verdict for PRIVILEGE_ESCALATION, got %s", verdict)
	}
}

func TestEvaluatePrivilegeEscalationAttemptIsSuspicious(t *testing.T) {
	verdict, _ := Evaluate([]Finding{
		{Severity: SeverityWarning, ReasonCode: "PRIVILEGE_ESCALATION_ATTEMPT"},
	}, defaultOpts)
	if verdict != VerdictSuspicious {
		t.Fatalf("expected suspicious verdict for PRIVILEGE_ESCALATION_ATTEMPT, got %s", verdict)
	}
}

func TestPrivilegedKernelOperationVerdicts(t *testing.T) {
	t.Run("failed attempt is suspicious", func(t *testing.T) {
		verdict, _ := Evaluate([]Finding{{
			Severity:   SeverityWarning,
			ReasonCode: "PRIVILEGED_KERNEL_OPERATION_ATTEMPT",
		}}, defaultOpts)
		if verdict != VerdictSuspicious {
			t.Fatalf("expected suspicious verdict for failed kernel operation, got %s", verdict)
		}
	})

	t.Run("successful operation is malicious", func(t *testing.T) {
		verdict, _ := Evaluate([]Finding{{
			Severity:   SeverityCritical,
			ReasonCode: "PRIVILEGED_KERNEL_OPERATION",
		}}, defaultOpts)
		if verdict != VerdictMalicious {
			t.Fatalf("expected malicious verdict for successful kernel operation, got %s", verdict)
		}
	})
}

func TestFailedPrivilegeOperationsShareSuspiciousCeiling(t *testing.T) {
	verdict, _ := Evaluate([]Finding{
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
	verdict, _ := Evaluate([]Finding{
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
	verdict, _ := Evaluate([]Finding{
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
	verdict, _ := Evaluate([]Finding{
		{Severity: SeverityCritical, ReasonCode: "ACCOUNT_FILE_ACCESS", Path: "/etc/shadow"},
	}, defaultOpts)
	if verdict != VerdictMalicious {
		t.Fatalf("expected malicious verdict for critical ACCOUNT_FILE_ACCESS, got %s", verdict)
	}
}

func TestEvaluatePasswdReadOnlyNotMalicious(t *testing.T) {
	// Simulates a clean non-root scan that only has registry traffic + no account findings.
	// (passwd reads are suppressed in the parser; ensure leftover info wouldn't hard-fail.)
	verdict, _ := Evaluate([]Finding{
		{Severity: SeverityInfo, ReasonCode: "EXTERNAL_NETWORK_REGISTRY"},
	}, defaultOpts)
	if verdict == VerdictMalicious {
		t.Fatalf("expected non-malicious clean install-like findings, got %s", verdict)
	}
}

func TestEvaluatePrivilegeEscalationAttemptWithMaliciousFinding(t *testing.T) {
	verdict, _ := Evaluate([]Finding{
		{Severity: SeverityWarning, ReasonCode: "PRIVILEGE_ESCALATION_ATTEMPT"},
		{Severity: SeverityCritical, ReasonCode: "CREDENTIAL_READ"},
	}, defaultOpts)
	if verdict != VerdictMalicious {
		t.Fatalf("expected malicious verdict when attempt combines with hard malicious finding, got %s", verdict)
	}
}

// Edge case tests for scoring
func TestEvaluate_ScoringEdgeCases(t *testing.T) {
	tests := []struct {
		name            string
		findings        []Finding
		expectedVerdict Verdict
		expectedScore   int
	}{
		{
			name: "Score 20 (CLEAN)",
			findings: []Finding{
				{Severity: SeverityWarning, ReasonCode: "POLICY_BLOCKED_DOMAIN"}, // 20
			},
			expectedVerdict: VerdictClean,
			expectedScore:   75,
		},
		{
			name: "Score 35 (SUSPICIOUS)",
			findings: []Finding{
				{Severity: SeverityWarning, ReasonCode: "CURL_PIPE_SHELL"}, // 35
			},
			expectedVerdict: VerdictSuspicious,
			expectedScore:   40 + (35 / 2),
		},
		{
			name: "Score 75 (SUSPICIOUS)",
			findings: []Finding{
				{Severity: SeverityWarning, ReasonCode: "STAGED_DOWNLOADER"},     // 55
				{Severity: SeverityWarning, ReasonCode: "POLICY_BLOCKED_DOMAIN"}, // 20
			},
			expectedVerdict: VerdictSuspicious,
			expectedScore:   40 + (75 / 2),
		},
		{
			name: "Score 90 (MALICIOUS)",
			findings: []Finding{
				{Severity: SeverityWarning, ReasonCode: "STAGED_DOWNLOADER"}, // 55
				{Severity: SeverityWarning, ReasonCode: "CURL_PIPE_SHELL"},   // 35
			},
			expectedVerdict: VerdictMalicious,
			expectedScore:   90,
		},
		{
			name: "Score cap at 100",
			findings: []Finding{
				{Severity: SeverityWarning, ReasonCode: "STAGED_DOWNLOADER"}, // 55
				{Severity: SeverityWarning, ReasonCode: "SUSPICIOUS_EXEC"},   // 55
				{Severity: SeverityWarning, ReasonCode: "CURL_PIPE_SHELL"},   // 35
			},
			expectedVerdict: VerdictMalicious,
			expectedScore:   100,
		},
		{
			name: "Critical overrides score",
			findings: []Finding{
				{Severity: SeverityCritical, ReasonCode: "UNKNOWN_CRITICAL"}, // weight 15 but Critical severity
			},
			expectedVerdict: VerdictMalicious,
			expectedScore:   80,
		},
		{
			name: "Critical wins over inconclusive runtime failure",
			findings: []Finding{
				{Severity: SeverityCritical, ReasonCode: "CREDENTIAL_READ"},     // Malicious
				{Severity: SeverityWarning, ReasonCode: "RUNTIME_PREP_FAILURE"}, // Inconclusive
			},
			expectedVerdict: VerdictMalicious,
			expectedScore:   100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict, confidence := Evaluate(tt.findings, defaultOpts)
			if verdict != tt.expectedVerdict {
				t.Errorf("expected verdict %s, got %s", tt.expectedVerdict, verdict)
			}
			if confidence != tt.expectedScore {
				t.Errorf("expected score/confidence %d, got %d", tt.expectedScore, confidence)
			}
		})
	}
}
