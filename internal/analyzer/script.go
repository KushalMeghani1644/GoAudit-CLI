package analyzer

import (
	"regexp"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
)

var suspiciousScriptPatterns = []struct {
	code       string
	pattern    *regexp.Regexp
	severity   report.Severity
	confidence int
}{
	{"STAGED_DOWNLOADER", regexp.MustCompile(`(?i)(curl|wget)[^|;\n]*(\||;).*?(sh|bash)`), report.SeverityCritical, 90},
	{"SCRIPT_OBFUSCATION", regexp.MustCompile(`(?i)(base64\s+-d|eval\s+\$?\(|python\s+-c\s+["'].*exec\()`), report.SeverityWarning, 80},
	{"PERSISTENCE_WRITE", regexp.MustCompile(`(?i)(/etc/cron|crontab|\.bashrc|\.zshrc|/etc/profile|authorized_keys)`), report.SeverityCritical, 90},
	{"CREDENTIAL_READ", regexp.MustCompile(`(?i)(\.aws/credentials|id_rsa|\.kube/config|\.env|\.git-credentials|\.npmrc)`), report.SeverityCritical, 85},
	{"REVERSE_SHELL", regexp.MustCompile(`(?i)(/dev/tcp/|nc\s+-e|bash\s+-i)`), report.SeverityCritical, 95},
	{"SUID_SGID_BIT_SET", regexp.MustCompile(`(?i)\bchmod(?:\s+--?[^\s]+)*\s+(?:0?[2-7][0-7]{3}|(?:a|u|g|\+)[+,a-z]*s)\s+(?:/usr/(?:local/)?bin/|/(?:s?bin|etc)/)`), report.SeverityCritical, 90},
}

func analyzeScriptBody(url, body string) []report.Finding {
	// Patterns are already case-insensitive; keep original body for evidence fidelity.
	var findings []report.Finding
	for _, s := range suspiciousScriptPatterns {
		if s.pattern.MatchString(body) {
			findings = append(findings, report.Finding{
				Severity:   s.severity,
				Type:       "script",
				ReasonCode: s.code,
				Path:       url,
				Confidence: s.confidence,
				Evidence:   "Matched static script detection pattern",
			})
		}
	}
	return findings
}
