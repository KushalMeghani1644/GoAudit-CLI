package analyzer

import (
	"testing"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
)

func TestAnalyzeScriptBodyDetectsSUIDPlanting(t *testing.T) {
	for _, body := range []string{
		"chmod 4755 /usr/local/bin/update-helper",
		"chmod 04755 /usr/bin/update-helper",
		"chmod u+s /bin/update-helper",
		"chmod a+s /usr/bin/update-helper",
	} {
		t.Run(body, func(t *testing.T) {
			findings := analyzeScriptBody("package.json:postinstall", body)
			if !hasReason(findings, "SUID_SGID_BIT_SET") {
				t.Fatalf("expected SUID_SGID_BIT_SET for %q, got %+v", body, findings)
			}
		})
	}
}

func TestAnalyzeScriptBodyIgnoresOrdinaryChmod(t *testing.T) {
	for _, body := range []string{
		"chmod 0755 /usr/local/bin/update-helper",
		"chmod 4755 ./test-fixture",
	} {
		t.Run(body, func(t *testing.T) {
			if findings := analyzeScriptBody("package.json:postinstall", body); hasReason(findings, "SUID_SGID_BIT_SET") {
				t.Fatalf("did not expect SUID finding for %q", body)
			}
		})
	}
}

func hasReason(findings []report.Finding, reason string) bool {
	for _, finding := range findings {
		if finding.ReasonCode == reason {
			return true
		}
	}
	return false
}
