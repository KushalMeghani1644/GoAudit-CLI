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

func TestFormatHumanReportPrivilegeAttemptIsInstallWarning(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityWarning, Type: "privilege", ReasonCode: "PRIVILEGE_ESCALATION_ATTEMPT", Path: "setuid(0) = -1 EPERM (Operation not permitted)", Evidence: "[install]"},
	}
	out := FormatHumanReport(findings, ReportMeta{Command: "npm install ./attempt"}, VerdictSuspicious, 62)
	if !containsAll(out,
		"Install-Time Warnings",
		"PRIVILEGE ESCALATION ATTEMPT: setuid(0) = -1 EPERM (Operation not permitted)",
	) {
		t.Fatalf("expected privilege attempt as install-time warning, got:\n%s", out)
	}
	if strings.Contains(out, "Static Analysis") || strings.Contains(out, "Sandbox Reliability") {
		t.Fatalf("expected privilege attempt to stay out of static/operational sections, got:\n%s", out)
	}
}

func TestFormatHumanReportPrivilegeEscalationIsInstallCritical(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityCritical, Type: "privilege", ReasonCode: "PRIVILEGE_ESCALATION", Path: "setuid(0) = 0", Evidence: "[install]"},
	}
	out := FormatHumanReport(findings, ReportMeta{Command: "npm install ./evil"}, VerdictMalicious, 80)
	if !containsAll(out,
		"Install-Time Behavior (observed in sandbox)",
		"PRIVILEGE ESCALATION: setuid(0) = 0",
	) {
		t.Fatalf("expected privilege escalation as install-time critical behavior, got:\n%s", out)
	}
}

func TestFormatHumanReportAccountFileAccessIsPrivilegeBehavior(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityCritical, Type: "privilege", ReasonCode: "ACCOUNT_FILE_ACCESS", Path: "/etc/shadow", Evidence: "[install]"},
	}
	out := FormatHumanReport(findings, ReportMeta{Command: "npm install ./evil"}, VerdictMalicious, 80)
	if !containsAll(out,
		"During install, the target accessed Unix account files such as /etc/passwd or /etc/shadow.",
		"PRIVILEGE-SENSITIVE ACCOUNT FILE ACCESS: /etc/shadow",
	) {
		t.Fatalf("expected account-file access to be reported as privilege-sensitive behavior, got:\n%s", out)
	}
}

func TestFormatHumanReportStyledAnsiToggle(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityCritical, Type: "fs_read", ReasonCode: "CREDENTIAL_READ", Path: "/etc/passwd", Evidence: "[install]"},
	}
	meta := ReportMeta{Command: "npm install ./evil"}

	outWithColor := FormatHumanReportStyled(findings, meta, VerdictMalicious, 100, HumanReportStyle{Color: true})
	if !strings.Contains(outWithColor, "\x1b[") {
		t.Fatalf("expected ANSI escapes in colorized output, got:\n%s", outWithColor)
	}

	outWithoutColor := FormatHumanReportStyled(findings, meta, VerdictMalicious, 100, HumanReportStyle{Color: false})
	if strings.Contains(outWithoutColor, "\x1b[") {
		t.Fatalf("did not expect ANSI escapes in non-color output, got:\n%s", outWithoutColor)
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
