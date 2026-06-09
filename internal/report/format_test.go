package report

import (
	"strings"
	"testing"
)

func TestFormatHumanReportSplitsInstallAndStatic(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityCritical, Type: "fs_read", ReasonCode: "CREDENTIAL_READ", Path: "/home/node/.ssh/id_rsa", Evidence: "[install]"},
		{Severity: SeverityCritical, Type: "npm", ReasonCode: "NPM_LIFECYCLE_CREDENTIAL_READ", Path: "evil-pkg@1.0.0:preinstall"},
		{Severity: SeverityInfo, Type: "runtime", ReasonCode: "RUNTIME_METADATA", Evidence: "phase=probe"},
	}
	out := FormatHumanReport(findings, ReportMeta{Command: "npm install ./evil"}, VerdictMalicious, 100)
	if !containsAll(out,
		"Install-Time Behavior (observed in sandbox)",
		"CREDENTIAL THEFT: /home/node/.ssh/id_rsa",
		"Runtime import probe completed without re-triggering malicious behavior",
		"Malicious activity was already observed during install-time sandbox tracing",
	) {
		t.Fatalf("expected split install/static report, got:\n%s", out)
	}
	if strings.Contains(out, "Static Analysis") {
		t.Fatalf("expected redundant static credential finding to be suppressed, got:\n%s", out)
	}
}

func TestFormatHumanReportProbeSummaryCleanWhenNoInstallRisk(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityInfo, Type: "runtime", ReasonCode: "RUNTIME_METADATA", Evidence: "phase=probe"},
	}
	out := FormatHumanReport(findings, ReportMeta{Command: "npm install lodash"}, VerdictClean, 90)
	if !strings.Contains(out, "Runtime import probe completed without suspicious behavior") {
		t.Fatalf("expected clean probe summary, got:\n%s", out)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}
