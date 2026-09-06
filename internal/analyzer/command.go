package analyzer

import (
	"strings"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
)

func AnalyzeCommand(command string) []report.Finding {
	cmd := strings.TrimSpace(command)
	if cmd == "" {
		return nil
	}

	var findings []report.Finding

	if strings.Contains(cmd, "npm install") && !strings.Contains(cmd, "--ignore-scripts") {
		findings = append(findings, report.Finding{
			Severity:   report.SeverityWarning,
			Type:       "command",
			ReasonCode: "NPM_LIFECYCLE_SCRIPTS",
			Path:       cmd,
			Confidence: 65,
			Evidence:   "npm install may execute lifecycle scripts (preinstall/install/postinstall)",
		})
	}
	if (strings.Contains(cmd, "pnpm add") || strings.Contains(cmd, "pnpm install")) && !strings.Contains(cmd, "--ignore-scripts") {
		findings = append(findings, report.Finding{
			Severity:   report.SeverityWarning,
			Type:       "command",
			ReasonCode: "PNPM_LIFECYCLE_SCRIPTS",
			Path:       cmd,
			Confidence: 65,
			Evidence:   "pnpm install/add may execute lifecycle scripts",
		})
	}
	if strings.Contains(cmd, "bun add") {
		findings = append(findings, report.Finding{
			Severity:   report.SeverityWarning,
			Type:       "command",
			ReasonCode: "BUN_INSTALL_SCRIPTS",
			Path:       cmd,
			Confidence: 65,
			Evidence:   "bun add may execute lifecycle scripts from packages",
		})
	}

	return findings
}
