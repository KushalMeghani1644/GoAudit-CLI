package report

import (
	"fmt"
	"sort"
	"strings"
)

type HumanReportStyle struct {
	Color bool
}

var knownRegistryHosts = map[string]bool{
	"registry.npmjs.org":     true,
	"registry.yarnpkg.com":   true,
	"registry.npmmirror.com": true,
}

func FormatHumanReport(findings []Finding, meta ReportMeta, verdict Verdict, confidence int) string {
	var b strings.Builder
	title := meta.Command
	if strings.TrimSpace(title) == "" {
		title = "scan"
	}

	b.WriteString("GoAudit Report\n")
	b.WriteString(fmt.Sprintf("Command: %s\n", title))

	switch verdict {
	case VerdictMalicious:
		b.WriteString(fmt.Sprintf("Verdict: %s (confidence: %d)\n", verdict, confidence))
	case VerdictSuspicious, VerdictInconclusive:
		b.WriteString(fmt.Sprintf("Verdict: %s (confidence: %d)\n", verdict, confidence))
	default:
		b.WriteString(fmt.Sprintf("Verdict: %s (confidence: %d)\n", verdict, confidence))
	}

	if meta.SandboxRuntime == "runsc" {
		b.WriteString("Sandbox: gVisor (runsc)\n")
	} else if meta.SandboxRuntime != "" {
		b.WriteString(fmt.Sprintf("Sandbox: %s (install gVisor for stronger isolation)\n", meta.SandboxRuntime))
	}

	if meta.PackageName != "" {
		if meta.PackageVersion != "" {
			b.WriteString(fmt.Sprintf("Package: %s@%s\n", meta.PackageName, meta.PackageVersion))
		} else {
			b.WriteString(fmt.Sprintf("Package: %s\n", meta.PackageName))
		}
	}

	displayFindings := suppressRedundantStatic(findings)

	installCritical, installWarnings := splitInstallDynamic(displayFindings, SeverityCritical), splitInstallDynamic(displayFindings, SeverityWarning)
	staticCritical, staticWarnings := splitStatic(displayFindings, SeverityCritical), splitStatic(displayFindings, SeverityWarning)
	probeCritical, probeWarnings := splitProbeDynamic(displayFindings, SeverityCritical), splitProbeDynamic(displayFindings, SeverityWarning)
	operationalWarnings := splitOperational(displayFindings, SeverityWarning)
	operationalCritical := splitOperational(displayFindings, SeverityCritical)
	info := filterBySeverity(displayFindings, SeverityInfo)

	writeBehaviorSummary(&b, installFindings(displayFindings), verdict)

	if len(installCritical) > 0 {
		b.WriteString("Install-Time Behavior (observed in sandbox)\n")
		writeFindingsList(&b, installCritical)
	}
	if len(installWarnings) > 0 {
		b.WriteString("Install-Time Warnings\n")
		writeFindingsList(&b, installWarnings)
	}

	writeProbeSummary(&b, displayFindings, len(installCritical)+len(installWarnings) > 0, len(probeCritical)+len(probeWarnings) > 0)

	if len(probeCritical) > 0 {
		b.WriteString("Runtime Probe Findings\n")
		writeFindingsList(&b, probeCritical)
	}
	if len(probeWarnings) > 0 {
		b.WriteString("Runtime Probe Warnings\n")
		writeFindingsList(&b, probeWarnings)
	}

	if len(staticCritical) > 0 {
		b.WriteString("Static Analysis\n")
		writeFindingsList(&b, staticCritical)
	}
	if len(staticWarnings) > 0 {
		b.WriteString("Static Warnings\n")
		writeFindingsList(&b, staticWarnings)
	}

	if len(operationalCritical) > 0 || len(operationalWarnings) > 0 {
		b.WriteString("Sandbox Reliability\n")
		writeFindingsList(&b, append(operationalCritical, operationalWarnings...))
	}

	writeNetworkSummary(&b, displayFindings)

	totalCritical := len(installCritical) + len(probeCritical) + len(staticCritical) + len(operationalCritical)
	totalWarnings := len(installWarnings) + len(probeWarnings) + len(staticWarnings) + len(operationalWarnings)
	b.WriteString(fmt.Sprintf("Summary: %d critical (%d install-time, %d probe, %d static), %d warnings, %d informational\n",
		totalCritical, len(installCritical), len(probeCritical), len(staticCritical), totalWarnings, len(info)))
	if verdict == VerdictMalicious {
		b.WriteString("   DO NOT INSTALL this package.\n")
	} else {
		b.WriteString("   Use --ci for full JSON output.\n")
	}
	return strings.ReplaceAll(b.String(), "\n", "\r\n")
}

func FormatHumanReportStyled(findings []Finding, meta ReportMeta, verdict Verdict, confidence int, style HumanReportStyle) string {
	var b strings.Builder
	title := meta.Command
	if strings.TrimSpace(title) == "" {
		title = "scan"
	}

	// Keep layout stable across terminals; only color depends on `style.Color`.
	horizontalRule := "────────────────────────────────────────────────────────────────"

	b.WriteString("GoAudit Report\n")
	b.WriteString(horizontalRule + "\n")
	b.WriteString(fmt.Sprintf("Command: %s\n", title))

	coloredVerdict := string(verdict)
	switch verdict {
	case VerdictMalicious:
		coloredVerdict = wrapANSI(style, "1;31", string(verdict))
	case VerdictSuspicious:
		coloredVerdict = wrapANSI(style, "1;33", string(verdict))
	case VerdictInconclusive:
		coloredVerdict = wrapANSI(style, "1;35", string(verdict))
	default:
		coloredVerdict = wrapANSI(style, "1;32", string(verdict))
	}
	b.WriteString(fmt.Sprintf("Verdict: %s (confidence: %d)\n", coloredVerdict, confidence))

	if meta.SandboxRuntime == "runsc" {
		b.WriteString("Sandbox: gVisor (runsc)\n")
	} else if meta.SandboxRuntime != "" {
		b.WriteString(fmt.Sprintf("Sandbox: %s (install gVisor for stronger isolation)\n", meta.SandboxRuntime))
	}

	if meta.PackageName != "" {
		if meta.PackageVersion != "" {
			b.WriteString(fmt.Sprintf("Package: %s@%s\n", meta.PackageName, meta.PackageVersion))
		} else {
			b.WriteString(fmt.Sprintf("Package: %s\n", meta.PackageName))
		}
	}

	b.WriteString("\n")

	displayFindings := suppressRedundantStatic(findings)
	installCritical, installWarnings := splitInstallDynamic(displayFindings, SeverityCritical), splitInstallDynamic(displayFindings, SeverityWarning)
	staticCritical, staticWarnings := splitStatic(displayFindings, SeverityCritical), splitStatic(displayFindings, SeverityWarning)
	probeCritical, probeWarnings := splitProbeDynamic(displayFindings, SeverityCritical), splitProbeDynamic(displayFindings, SeverityWarning)
	operationalWarnings := splitOperational(displayFindings, SeverityWarning)
	operationalCritical := splitOperational(displayFindings, SeverityCritical)
	info := filterBySeverity(displayFindings, SeverityInfo)

	// Behavior summary (plain text body, but with clearer section boundaries).
	writeBehaviorSummary(&b, installFindings(displayFindings), verdict)

	if len(installCritical) > 0 {
		b.WriteString("\n")
		b.WriteString("Install-Time Behavior (observed in sandbox)\n")
		b.WriteString(horizontalRule + "\n")
		writeFindingsListStyled(&b, installCritical, style)
	}
	if len(installWarnings) > 0 {
		b.WriteString("\n")
		b.WriteString("Install-Time Warnings\n")
		b.WriteString(horizontalRule + "\n")
		writeFindingsListStyled(&b, installWarnings, style)
	}

	writeProbeSummary(&b, displayFindings, len(installCritical)+len(installWarnings) > 0, len(probeCritical)+len(probeWarnings) > 0)

	if len(probeCritical) > 0 {
		b.WriteString("\n")
		b.WriteString("Runtime Probe Findings\n")
		b.WriteString(horizontalRule + "\n")
		writeFindingsListStyled(&b, probeCritical, style)
	}
	if len(probeWarnings) > 0 {
		b.WriteString("\n")
		b.WriteString("Runtime Probe Warnings\n")
		b.WriteString(horizontalRule + "\n")
		writeFindingsListStyled(&b, probeWarnings, style)
	}

	if len(staticCritical) > 0 {
		b.WriteString("\n")
		b.WriteString("Static Analysis\n")
		b.WriteString(horizontalRule + "\n")
		writeFindingsListStyled(&b, staticCritical, style)
	}
	if len(staticWarnings) > 0 {
		b.WriteString("\n")
		b.WriteString("Static Warnings\n")
		b.WriteString(horizontalRule + "\n")
		writeFindingsListStyled(&b, staticWarnings, style)
	}

	if len(operationalCritical) > 0 || len(operationalWarnings) > 0 {
		b.WriteString("\n")
		b.WriteString("Sandbox Reliability\n")
		b.WriteString(horizontalRule + "\n")
		writeFindingsListStyled(&b, append(operationalCritical, operationalWarnings...), style)
	}

	b.WriteString("\n")
	writeNetworkSummary(&b, displayFindings)

	totalCritical := len(installCritical) + len(probeCritical) + len(staticCritical) + len(operationalCritical)
	totalWarnings := len(installWarnings) + len(probeWarnings) + len(staticWarnings) + len(operationalWarnings)
	b.WriteString(fmt.Sprintf("Summary: %s critical (%d install-time, %d probe, %d static), %s warnings, %d informational\n",
		joinColoredCounts(style, strconvI(totalCritical), "1;31"),
		len(installCritical), len(probeCritical), len(staticCritical),
		joinColoredCounts(style, strconvI(totalWarnings), "1;33"),
		len(info)))

	if verdict == VerdictMalicious {
		b.WriteString(wrapANSI(style, "1;31", "   DO NOT INSTALL this package.") + "\n")
	} else {
		b.WriteString(wrapANSI(style, "1;36", "   Use --ci for full JSON output.") + "\n")
	}

	return strings.ReplaceAll(b.String(), "\n", "\r\n")
}

func writeFindingsListStyled(b *strings.Builder, findings []Finding, style HumanReportStyle) {
	for i, f := range findings {
		ex := ExplainReason(f.ReasonCode)
		title := ex.Title
		if title == "" {
			title = f.ReasonCode
		}

		context := findingContext(f)
		sevPrefix, titleColor := severityPrefixAndColor(style, f.Severity)
		upperTitle := strings.ToUpper(title)

		if context != "" {
			b.WriteString(fmt.Sprintf("   %d. %s %s: %s\n", i+1, sevPrefix, wrapMaybe(style, titleColor, upperTitle), context))
		} else {
			b.WriteString(fmt.Sprintf("   %d. %s %s\n", i+1, sevPrefix, wrapMaybe(style, titleColor, upperTitle)))
		}

		detail := lifecycleDetail(f, ex.Detail)
		if detail != "" {
			b.WriteString(fmt.Sprintf("      Details: %s\n", detail))
		}
	}
}

func severityPrefixAndColor(style HumanReportStyle, sev Severity) (string, string) {
	switch sev {
	case SeverityCritical:
		return wrapANSI(style, "1;31", "[CRITICAL]"), "1;31"
	case SeverityWarning:
		return wrapANSI(style, "1;33", "[WARNING]"), "1;33"
	default:
		return wrapANSI(style, "1;36", "[INFO]"), "1;36"
	}
}

func wrapMaybe(style HumanReportStyle, ansiCode string, text string) string {
	if !style.Color {
		return text
	}
	return "\x1b[" + ansiCode + "m" + text + "\x1b[0m"
}

func wrapANSI(style HumanReportStyle, ansiCode string, text string) string {
	if !style.Color {
		return text
	}
	return "\x1b[" + ansiCode + "m" + text + "\x1b[0m"
}

func joinColoredCounts(style HumanReportStyle, value string, ansiCode string) string {
	if !style.Color {
		return value
	}
	return "\x1b[" + ansiCode + "m" + value + "\x1b[0m"
}

func strconvI(i int) string {
	// local helper to avoid importing strconv at the top of the file just for formatting.
	return fmt.Sprintf("%d", i)
}

func writeBehaviorSummary(b *strings.Builder, findings []Finding, verdict Verdict) {
	observations := behaviorObservations(findings)
	b.WriteString("What GoAudit Observed\n")
	if len(observations) == 0 {
		if verdict == VerdictClean {
			b.WriteString("   1. GoAudit installed and observed the target in a sandbox.\n")
			b.WriteString("   2. It did not observe credential reads, persistence writes, suspicious process execution, or unexpected outbound network connections.\n")
		} else {
			b.WriteString("   1. GoAudit did not collect enough clear behavioral evidence to describe the run.\n")
		}
		return
	}
	for i, observation := range observations {
		b.WriteString(fmt.Sprintf("   %d. %s\n", i+1, observation))
	}
}

func behaviorObservations(findings []Finding) []string {
	seen := map[string]bool{}
	var observations []string
	add := func(key, text string) {
		if seen[key] {
			return
		}
		seen[key] = true
		observations = append(observations, text)
	}
	for _, f := range findings {
		switch f.ReasonCode {
		case "CREDENTIAL_READ":
			add("credentials", "During install, the target read credential-like files such as cloud credentials, SSH keys, Kubernetes config, npm tokens, or .env files.")
		case "ENV_THEFT":
			add("env", "During install, the target read /proc/self/environ, which exposes process environment variables and secrets.")
		case "PERSISTENCE_WRITE":
			add("persistence", "During install, the target modified files commonly used for persistence, such as shell startup files, cron, or SSH authorized keys.")
		case "SYMLINK_SENSITIVE_PATH":
			add("symlink", "During install, the target created symlinks that point at sensitive credential paths.")
		case "SUSPICIOUS_EXEC":
			add("exec", "During install, the target executed a suspicious program or shell command.")
		case "PRIVILEGE_ESCALATION":
			add("privilege-escalation", "During install, the target successfully switched to root UID/GID inside the sandbox.")
		case "PRIVILEGE_ESCALATION_ATTEMPT":
			add("privilege-attempt", "During install, the target attempted to switch to root UID/GID, but the sandbox denied it.")
		case "PRIVILEGE_ESCALATION_EXEC":
			add("privilege-helper", "During install, the target invoked a privilege escalation helper such as sudo, su, or pkexec.")
		case "SUID_SGID_BIT_SET":
			add("suid-sgid", "During install, the target attempted to set SUID or SGID permission bits for elevated future execution.")
		case "CAPABILITY_ESCALATION":
			add("capability", "During install, the target attempted to grant Linux capabilities to an executable.")
		case "NAMESPACE_ESCAPE_ATTEMPT":
			add("namespace", "During install, the target invoked namespace tooling commonly used for sandbox or container escape attempts.")
		case "LD_PRELOAD_PRIVILEGE_ATTEMPT":
			add("ld-preload", "During install, the target attempted LD_PRELOAD injection against a privileged helper.")
		case "ACCOUNT_FILE_ACCESS":
			add("account-file", "During install, the target accessed Unix account files such as /etc/passwd or /etc/shadow.")
		case "DATA_EXFIL":
			where := f.Host
			if where == "" {
				where = f.IP
			}
			if f.Port > 0 && where != "" {
				where = fmt.Sprintf("%s:%d", where, f.Port)
			}
			if where == "" {
				where = "a non-registry host"
			}
			add("exfil", fmt.Sprintf("During install, the target attempted to exfiltrate data to %s after accessing credentials.", where))
		case "EXTERNAL_NETWORK", "INTERNAL_NETWORK", "CLOUD_METADATA_ACCESS":
			where := f.Host
			if where == "" {
				where = f.IP
			}
			if f.Port > 0 && where != "" {
				where = fmt.Sprintf("%s:%d", where, f.Port)
			}
			if where == "" {
				where = "an external host"
			}
			if f.ReasonCode == "CLOUD_METADATA_ACCESS" {
				add("metadata", "During install, the target attempted to contact the cloud metadata service, a common way to steal cloud credentials.")
			} else if f.ReasonCode == "INTERNAL_NETWORK" {
				add("internal-network", fmt.Sprintf("During install, the target attempted to contact an internal or link-local network address: %s.", where))
			} else {
				add("network", fmt.Sprintf("During install, the target attempted an unexpected outbound network connection to %s.", where))
			}
		case "BACKDOOR_LISTENER":
			add("listener", fmt.Sprintf("During install, the target opened a listening network port inside the sandbox: %d.", f.Port))
		case "TARGET_COMMAND_TIMEOUT":
			add("timeout", "The target did not finish before GoAudit's timeout, so the report includes behavior observed before timeout.")
		case "RUNTIME_TRACE_UNAVAILABLE":
			add("trace", "GoAudit could not fully verify one sandbox trace phase; reliability details are listed below.")
		}
	}
	return observations
}

func writeFindingsList(b *strings.Builder, findings []Finding) {
	for i, f := range findings {
		ex := ExplainReason(f.ReasonCode)
		title := ex.Title
		if title == "" {
			title = f.ReasonCode
		}
		context := findingContext(f)
		if context != "" {
			b.WriteString(fmt.Sprintf("   %d. %s: %s\n", i+1, strings.ToUpper(title), context))
		} else {
			b.WriteString(fmt.Sprintf("   %d. %s\n", i+1, strings.ToUpper(title)))
		}
		detail := lifecycleDetail(f, ex.Detail)
		if detail != "" {
			b.WriteString(fmt.Sprintf("      Details: %s\n", detail))
		}
	}
}

func lifecycleDetail(f Finding, fallback string) string {
	switch f.ReasonCode {
	case "NPM_LIFECYCLE_STAGED_DOWNLOADER", "PNPM_LIFECYCLE_STAGED_DOWNLOADER", "BUN_LIFECYCLE_STAGED_DOWNLOADER",
		"NPM_LIFECYCLE_REVERSE_SHELL", "PNPM_LIFECYCLE_REVERSE_SHELL", "BUN_LIFECYCLE_REVERSE_SHELL",
		"NPM_LIFECYCLE_CREDENTIAL_READ", "PNPM_LIFECYCLE_CREDENTIAL_READ", "BUN_LIFECYCLE_CREDENTIAL_READ",
		"NPM_LIFECYCLE_SCRIPT_OBFUSCATION", "PNPM_LIFECYCLE_SCRIPT_OBFUSCATION", "BUN_LIFECYCLE_SCRIPT_OBFUSCATION",
		"NPM_LIFECYCLE_PERSISTENCE_WRITE", "PNPM_LIFECYCLE_PERSISTENCE_WRITE", "BUN_LIFECYCLE_PERSISTENCE_WRITE":
		if f.Path == "" {
			return "Lifecycle script matched a dangerous pattern during static analysis"
		}
		if idx := strings.LastIndex(f.Path, ":"); idx >= 0 && idx < len(f.Path)-1 {
			return fmt.Sprintf("%s script matched a dangerous pattern during static analysis", f.Path[idx+1:])
		}
		return "Lifecycle script matched a dangerous pattern during static analysis"
	default:
		return fallback
	}
}

func findingContext(f Finding) string {
	switch {
	case f.Path != "":
		return f.Path
	case f.Host != "":
		if f.Port > 0 {
			return fmt.Sprintf("%s:%d", f.Host, f.Port)
		}
		return f.Host
	case f.IP != "":
		if f.Port > 0 {
			return fmt.Sprintf("%s:%d", f.IP, f.Port)
		}
		return f.IP
	default:
		return ""
	}
}

func writeNetworkSummary(b *strings.Builder, findings []Finding) {
	type hostStats struct {
		host  string
		conns int
	}
	counts := map[string]int{}
	registryOnly := true
	for _, f := range findings {
		if f.Type != "network" {
			continue
		}
		host := f.Host
		if host == "" {
			host = f.IP
		}
		if host == "" {
			host = "unknown-host"
		}
		counts[host]++
		if f.ReasonCode != "EXTERNAL_NETWORK_REGISTRY" {
			registryOnly = false
		}
	}
	if len(counts) == 0 {
		return
	}

	hosts := make([]hostStats, 0, len(counts))
	total := 0
	for host, c := range counts {
		hosts = append(hosts, hostStats{host: host, conns: c})
		total += c
	}
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].conns == hosts[j].conns {
			return hosts[i].host < hosts[j].host
		}
		return hosts[i].conns > hosts[j].conns
	})

	if registryOnly {
		b.WriteString("Network Activity (expected)\n")
	} else {
		b.WriteString("Network Activity\n")
	}
	for _, h := range hosts {
		annotation := ""
		if knownRegistryHosts[strings.ToLower(h.host)] {
			annotation = " (registry)"
		}
		b.WriteString(fmt.Sprintf("   - %d connection(s) to %s%s\n", h.conns, h.host, annotation))
	}
	b.WriteString(fmt.Sprintf("   - %d connection(s) to %d host(s)\n", total, len(hosts)))
}

func writeProbeSummary(b *strings.Builder, findings []Finding, hasInstallRisk, hasProbeRisk bool) {
	hasProbeMeta := false
	for _, f := range findings {
		if f.ReasonCode == "RUNTIME_METADATA" && strings.Contains(f.Evidence, "phase=probe") {
			hasProbeMeta = true
			break
		}
	}
	if !hasProbeMeta {
		return
	}
	b.WriteString("Runtime Probe\n")
	switch {
	case hasProbeRisk:
		b.WriteString("   - Runtime import probe observed suspicious behavior\n")
	case hasInstallRisk:
		b.WriteString("   - Runtime import probe completed without re-triggering malicious behavior\n")
		b.WriteString("   - Malicious activity was already observed during install-time sandbox tracing\n")
	default:
		b.WriteString("   - Runtime import probe completed without suspicious behavior\n")
		b.WriteString("   - No credential access, suspicious writes, or unknown exfiltration detected during import\n")
	}
}

func isProbeFinding(f Finding) bool {
	return strings.Contains(f.Evidence, "[runtime probe]")
}

func isInstallFinding(f Finding) bool {
	return isDynamicFinding(f) && !isProbeFinding(f)
}

func isDynamicFinding(f Finding) bool {
	switch f.ReasonCode {
	case "RUNTIME_METADATA", "RUNTIME_MISSING_TOOL", "RUNTIME_PREP_FAILURE", "RUNTIME_TRACE_UNAVAILABLE",
		"RUNTIME_PROJECT_COPY_FAILURE", "RUNSC_FALLBACK_RUNC", "RUNSC_TRACE_FALLBACK_RUNC",
		"TARGET_COMMAND_FAILED", "TARGET_COMMAND_NOT_FOUND", "TARGET_COMMAND_TIMEOUT":
		return false
	}
	switch f.Type {
	case "fs_read", "fs_write", "exec", "network", "privilege":
		return true
	}
	return false
}

func isStaticFinding(f Finding) bool {
	if isDynamicFinding(f) {
		return false
	}
	switch f.Type {
	case "command", "script", "npm", "pnpm", "bun", "policy":
		return true
	}
	if strings.HasPrefix(f.ReasonCode, "NPM_") || strings.HasPrefix(f.ReasonCode, "PNPM_") || strings.HasPrefix(f.ReasonCode, "BUN_") {
		return true
	}
	switch f.ReasonCode {
	case "CURL_PIPE_SHELL", "SCRIPT_OBFUSCATION", "STAGED_DOWNLOADER", "REVERSE_SHELL",
		"POLICY_BLOCKED_DOMAIN", "INCONCLUSIVE_REMOTE_FETCH", "INCONCLUSIVE_NPM_METADATA",
		"INCONCLUSIVE_PNPM_METADATA", "INCONCLUSIVE_BUN_METADATA", "SCRIPT_FETCHED":
		return true
	}
	return false
}

func installFindings(findings []Finding) []Finding {
	out := make([]Finding, 0)
	for _, f := range findings {
		if isInstallFinding(f) {
			out = append(out, f)
		}
	}
	return out
}

func splitInstallDynamic(findings []Finding, severity Severity) []Finding {
	out := make([]Finding, 0)
	for _, f := range findings {
		if f.Severity == severity && isInstallFinding(f) {
			out = append(out, f)
		}
	}
	return out
}

func splitProbeDynamic(findings []Finding, severity Severity) []Finding {
	out := make([]Finding, 0)
	for _, f := range findings {
		if f.Severity == severity && isProbeFinding(f) && isDynamicFinding(f) {
			out = append(out, f)
		}
	}
	return out
}

func splitStatic(findings []Finding, severity Severity) []Finding {
	out := make([]Finding, 0)
	for _, f := range findings {
		if f.Severity == severity && isStaticFinding(f) {
			out = append(out, f)
		}
	}
	return out
}

func splitOperational(findings []Finding, severity Severity) []Finding {
	out := make([]Finding, 0)
	for _, f := range findings {
		if f.Severity == severity && isOperationalFinding(f) {
			out = append(out, f)
		}
	}
	return out
}

func isOperationalFinding(f Finding) bool {
	switch f.ReasonCode {
	case "RUNTIME_MISSING_TOOL", "RUNTIME_PREP_FAILURE", "RUNTIME_TRACE_UNAVAILABLE",
		"RUNTIME_PROJECT_COPY_FAILURE", "RUNSC_FALLBACK_RUNC", "RUNSC_TRACE_FALLBACK_RUNC",
		"TARGET_COMMAND_FAILED", "TARGET_COMMAND_NOT_FOUND", "TARGET_COMMAND_TIMEOUT":
		return true
	}
	return false
}

func suppressRedundantStatic(findings []Finding) []Finding {
	confirmed := map[string]bool{}
	for _, f := range findings {
		if !isInstallFinding(f) {
			continue
		}
		switch f.ReasonCode {
		case "CREDENTIAL_READ", "ENV_THEFT":
			confirmed["credential"] = true
		case "PERSISTENCE_WRITE":
			confirmed["persistence"] = true
		case "DATA_EXFIL", "EXTERNAL_NETWORK", "INTERNAL_NETWORK":
			confirmed["network"] = true
		case "SUSPICIOUS_EXEC", "REVERSE_SHELL":
			confirmed["exec"] = true
		}
	}

	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if !isStaticFinding(f) || !strings.Contains(f.ReasonCode, "LIFECYCLE_") {
			out = append(out, f)
			continue
		}
		switch {
		case strings.Contains(f.ReasonCode, "CREDENTIAL_READ") && confirmed["credential"]:
			continue
		case strings.Contains(f.ReasonCode, "PERSISTENCE_WRITE") && confirmed["persistence"]:
			continue
		case strings.Contains(f.ReasonCode, "STAGED_DOWNLOADER") && confirmed["network"]:
			continue
		case strings.Contains(f.ReasonCode, "REVERSE_SHELL") && confirmed["exec"]:
			continue
		default:
			out = append(out, f)
		}
	}
	return out
}

func filterBySeverity(findings []Finding, severity Severity) []Finding {
	out := make([]Finding, 0)
	for _, f := range findings {
		if f.Severity == severity {
			out = append(out, f)
		}
	}
	return out
}

func trimWithEllipsis(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
