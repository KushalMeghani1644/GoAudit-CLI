package parser

import (
	"strings"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
)

// Probe diagnostics describe execution coverage, not malicious behavior. Keep
// their payload intact so JSON consumers can identify the package and exercise.
func parseProbeDiagnostic(line string) (report.Finding, bool) {
	line = strings.TrimSpace(line)
	for _, spec := range []struct {
		code     string
		severity report.Severity
		evidence string
	}{
		{"PROBE_API_OK", report.SeverityInfo, "Supported API adapter completed"},
		{"PROBE_API_FAILED", report.SeverityWarning, "Supported API adapter failed"},
		{"PROBE_API_UNSUPPORTED", report.SeverityInfo, "No supported API adapter was exercised"},
		{"PROBE_BIN_OK", report.SeverityInfo, "Declared CLI entrypoint completed with --help"},
		{"PROBE_BIN_FAIL", report.SeverityWarning, "Declared CLI entrypoint failed or was rejected"},
		{"PROBE_OBSERVATION_COMPLETE", report.SeverityInfo, "Short post-load observation window completed"},
		{"PROBE_OBSERVATION_INCOMPLETE", report.SeverityWarning, "Post-load observation window was incomplete"},
		{"PROBE_PACKAGE_TIMEOUT", report.SeverityWarning, "Package exercise exceeded its allocated budget"},
		{"PROBE_COVERAGE", report.SeverityInfo, "Package exercise coverage"},
		{"PROBE_SOURCE_SCAN", report.SeverityInfo, "Bounded entrypoint source inspection"},
		{"PROBE_OBFUSCATION", report.SeverityWarning, "Entrypoint contains a decode-to-execute obfuscation indicator; this is not proof of malware"},
	} {
		marker := "GOAUDIT_" + spec.code + ":"
		if !strings.HasPrefix(line, marker) {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, marker))
		f := report.Finding{
			Severity: spec.severity, Type: "runtime", ReasonCode: spec.code,
			Path: payload, Evidence: spec.evidence,
		}
		if spec.code == "PROBE_COVERAGE" && strings.HasSuffix(payload, ":incomplete") {
			f.Severity = report.SeverityWarning
		}
		if spec.code == "PROBE_OBFUSCATION" {
			f.Type = "script"
		}
		return f, true
	}
	return report.Finding{}, false
}
