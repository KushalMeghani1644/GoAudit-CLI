package report

import (
	"strings"
	"testing"
)

func TestProbeCoverageFailureVerdicts(t *testing.T) {
	for _, code := range []string{
		"PROBE_IMPORT_FAILED", "PROBE_BIN_FAIL", "PROBE_API_FAILED",
		"PROBE_PACKAGE_TIMEOUT", "PROBE_OBSERVATION_INCOMPLETE", "PROBE_COVERAGE",
	} {
		t.Run(code, func(t *testing.T) {
			f := Finding{Severity: SeverityWarning, Type: "runtime", ReasonCode: code, Path: "pkg:incomplete"}
			if got := Evaluate([]Finding{f}, EvaluationOptions{}); got != VerdictInconclusive {
				t.Fatalf("coverage failure should be inconclusive, got %s", got)
			}
			credential := Finding{Severity: SeverityCritical, Type: "fs_read", ReasonCode: "CREDENTIAL_READ"}
			if got := Evaluate([]Finding{f, credential}, EvaluationOptions{}); got != VerdictMalicious {
				t.Fatalf("coverage failure must not hide malicious evidence, got %s", got)
			}
		})
	}
}

func TestProbeSummaryReportsPartialCoverage(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityInfo, Type: "runtime", ReasonCode: "RUNTIME_METADATA", Evidence: "phase=probe"},
		{Severity: SeverityWarning, Type: "runtime", ReasonCode: "PROBE_IMPORT_FAILED", Path: "browser-only:ERR_LOAD"},
		{Severity: SeverityInfo, Type: "runtime", ReasonCode: "PROBE_API_OK", Path: "lodash:chunk"},
	}
	out := FormatHumanReport(findings, ReportMeta{}, VerdictInconclusive)
	for _, want := range []string{"coverage was incomplete", "browser-only:ERR_LOAD", "lodash:chunk", "not a safety guarantee"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q from report:\n%s", want, out)
		}
	}
	if strings.Contains(out, "completed without suspicious behavior") {
		t.Fatal("partial runtime coverage must not imply successful completion")
	}
}

func TestProbeWarningsCountInPlainAndStyledReports(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityInfo, Type: "runtime", ReasonCode: "RUNTIME_METADATA", Evidence: "phase=probe"},
		{Severity: SeverityWarning, Type: "runtime", ReasonCode: "PROBE_COVERAGE", Path: "pkg:incomplete"},
	}
	for _, output := range []string{
		FormatHumanReport(findings, ReportMeta{}, VerdictInconclusive),
		FormatHumanReportStyled(findings, ReportMeta{}, VerdictInconclusive, HumanReportStyle{}),
	} {
		if !strings.Contains(output, "1 warnings") || !strings.Contains(output, "Sandbox Reliability") {
			t.Fatalf("coverage warning missing from totals/reliability section:\n%s", output)
		}
	}
}
