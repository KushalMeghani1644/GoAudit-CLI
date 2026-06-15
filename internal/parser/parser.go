package parser

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
)

// HasPrepFailure reports whether sandbox container logs indicate prep_failed.
func HasPrepFailure(findings []report.Finding) bool {
	for _, f := range findings {
		if f.ReasonCode == "RUNTIME_PREP_FAILURE" {
			return true
		}
	}
	return false
}

var (
	fsRegex   = regexp.MustCompile(`(?i)(?:open|openat|openat2).*?\"(.*?)\",\s*(?:\{[^}]*flags=)?([A-Z_\|]+)`)
	netRegex  = regexp.MustCompile(`connect\(.*sa_family=(?:AF_INET|AF_INET6).*?sin6?_port=htons\((\d+)\).*?(?:inet_addr\("(.*?)"\)|inet_pton\([^,]+,\s*"(.*?)")`)
	execRegex = regexp.MustCompile(`(?i)execve\(\"(.*?)\",\s*\[(.*?)\]`)
	mutRegex  = regexp.MustCompile(`(?i)(?:chmod|fchmod|fchmodat|rename|unlink|unlinkat)\(\"?(.*?)\"?[,)]`)
	privRegex = regexp.MustCompile(`(?i)(setuid|setgid|setreuid|setregid)\(([^)]*)\)`)

	readCriticalPaths  = regexp.MustCompile(`(?i)((?:^|.*?/)\.env(?:\b|$)|.*?/\.ssh/.*?|.*?/\.aws/.*?|.*?/\.kube/.*?|.*?/\.git-credentials|.*?/\.npmrc|.*?id_rsa)`)
	writeCriticalPaths = regexp.MustCompile(`(?i)(.*?/\.bashrc|.*?/\.zshrc|.*?/\.profile|.*?/\.ssh/authorized_keys|^/etc/crontab|^/etc/cron\..*|^/usr/local/bin/.*|^/usr/bin/.*)`)
	writeAllowedPaths  = regexp.MustCompile(`(?i)(^/tmp/|^/dev/|^/proc/|^/sys/|^/workspace/|node_modules/|\.npm/|\.cache/|site-packages/|/var/tmp/|/pnpm/store/|pnpm-state\.json|^/usr/local/lib/|^/usr/lib/|(^|/)package(-lock)?\.json$|(^|/)pnpm-lock\.yaml$|(^|/)bun\.lockb?$|\.hm$|^/root/\.config/|^/home/.*?/\.config/|^/root/\.local/|^/home/.*?/\.local/|^/root/\.bun/|^/home/.*?/\.bun/)`)

	execSuspiciousBinaries = regexp.MustCompile(`(?i)(.*?/nc$|.*?/ncat$|.*?/netcat$|^/tmp/.*)`)

	symlinkRegex      = regexp.MustCompile(`(?i)(?:symlink|symlinkat)\("(.*?)",\s*(?:\d+,\s*)?"(.*?)"`)
	memfdRegex        = regexp.MustCompile(`(?i)memfd_create\("(.*?)"`)
	ptraceAttachRegex = regexp.MustCompile(`(?i)ptrace\(PTRACE_(?:ATTACH|SEIZE)`)
	bindListenRegex   = regexp.MustCompile(`(?:bind|listen)\(\d+,\s*\{sa_family=AF_INET6?,\s*sin6?_port=htons\((\d+)\)`)
	sendRegex         = regexp.MustCompile(`(?i)(?:sendto|sendmsg)\(\d+`)

	// Environment variable theft — reading /proc/self/environ
	procEnvironRegex = regexp.MustCompile(`(?i)open(?:at)?\(.*?"/proc/self/environ"`)
)

// ParseOptions configures the parser for the current scan context.
type ParseOptions struct {
	// KnownRegistryIPs maps IP addresses to their registry hostname.
	// Connections to these IPs are classified as EXTERNAL_NETWORK_REGISTRY.
	KnownRegistryIPs map[string]string

	// ProbeExpected is true when the scan appended a runtime probe script.
	ProbeExpected bool
}

func ParseStream(r io.Reader, reporter *report.Reporter, opts ParseOptions) ([]report.Finding, error) {
	findings, _, err := ParseStreamWithHealth(r, reporter, opts)
	return findings, err
}

type TraceHealth struct {
	TargetPhaseObserved   bool
	TargetExitObserved    bool
	TargetExitCode        int
	TargetSyscallObserved bool
	ProbeExpected         bool
	ProbePhaseObserved    bool
	ProbeExitObserved     bool
	ProbeExitCode         int
	ProbeSyscallObserved  bool
}

func (h TraceHealth) Usable() bool {
	if !h.TargetPhaseObserved || !h.TargetExitObserved || !h.TargetSyscallObserved {
		return false
	}
	if h.ProbeExpected && (!h.ProbePhaseObserved || !h.ProbeExitObserved || !h.ProbeSyscallObserved) {
		return false
	}
	if h.ProbeExpected && h.ProbeExitObserved && h.ProbeExitCode != 0 {
		return false
	}
	return true
}

type observedConnection struct {
	Host string
	IP   string
	Port int
}

func ParseStreamWithHealth(r io.Reader, reporter *report.Reporter, opts ParseOptions) ([]report.Finding, TraceHealth, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var findings []report.Finding
	probePhase := false
	targetPhase := false
	health := TraceHealth{ProbeExpected: opts.ProbeExpected}
	seen := map[string]bool{} // deduplication key
	sawSuspiciousOutbound := false
	lastSuspicious := observedConnection{}
	suspiciousByFD := map[string]observedConnection{}

	if opts.KnownRegistryIPs == nil {
		opts.KnownRegistryIPs = map[string]string{}
	}

	emit := func(f report.Finding) {
		if tag := phaseTag(probePhase, targetPhase); tag != "" && f.ReasonCode != "RUNTIME_METADATA" {
			f.Evidence = appendPhaseEvidence(f.Evidence, tag)
			if tag == "[runtime probe]" && f.Confidence < 95 && f.Severity != report.SeverityInfo {
				f.Confidence += 5
			}
		}
		findings = append(findings, f)
		reporter.PrintLiveFinding(f)
	}

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "GOAUDIT_RUNTIME_ERROR:missing_tool:") {
			tool := strings.TrimSpace(strings.TrimPrefix(line[strings.Index(line, "GOAUDIT_RUNTIME_ERROR:missing_tool:"):], "GOAUDIT_RUNTIME_ERROR:missing_tool:"))
			emit(report.Finding{Severity: report.SeverityWarning, Type: "runtime", ReasonCode: "RUNTIME_MISSING_TOOL", Path: tool, Confidence: 90})
			continue
		}
		if strings.Contains(line, "GOAUDIT_RUNTIME_ERROR:prep_failed") {
			emit(report.Finding{Severity: report.SeverityWarning, Type: "runtime", ReasonCode: "RUNTIME_PREP_FAILURE", Path: "sandbox prep failed", Confidence: 90})
			continue
		}
		if strings.Contains(line, "GOAUDIT_RUNTIME_ERROR:project_copy_failed") {
			emit(report.Finding{Severity: report.SeverityWarning, Type: "runtime", ReasonCode: "RUNTIME_PROJECT_COPY_FAILURE", Path: "project mount", Confidence: 90})
			continue
		}
		if strings.Contains(line, "GOAUDIT_PROBE_IMPORT_OK:") {
			pkg := strings.TrimSpace(line[strings.Index(line, "GOAUDIT_PROBE_IMPORT_OK:")+len("GOAUDIT_PROBE_IMPORT_OK:"):])
			emit(report.Finding{Severity: report.SeverityInfo, Type: "runtime", ReasonCode: "PROBE_IMPORT_OK", Path: pkg, Confidence: 90})
			continue
		}
		if strings.Contains(line, "GOAUDIT_PROBE_IMPORT_FAILED:") {
			pkg := strings.TrimSpace(line[strings.Index(line, "GOAUDIT_PROBE_IMPORT_FAILED:")+len("GOAUDIT_PROBE_IMPORT_FAILED:"):])
			emit(report.Finding{Severity: report.SeverityWarning, Type: "runtime", ReasonCode: "PROBE_IMPORT_FAILED", Path: pkg, Confidence: 70})
			continue
		}
		if strings.Contains(line, "GOAUDIT_PROBE_TIMEOUT") {
			emit(report.Finding{Severity: report.SeverityWarning, Type: "runtime", ReasonCode: "PROBE_COMMAND_TIMEOUT", Path: "124", Confidence: 95, Evidence: "Runtime probe timed out"})
			continue
		}
		if strings.Contains(line, "GOAUDIT_RUNTIME_META:") {
			meta := strings.TrimSpace(line[strings.Index(line, "GOAUDIT_RUNTIME_META:")+len("GOAUDIT_RUNTIME_META:"):])
			if strings.Contains(meta, "phase=probe") {
				probePhase = true
				targetPhase = true
				health.ProbePhaseObserved = true
				sawSuspiciousOutbound = false
				lastSuspicious = observedConnection{}
			}
			if strings.Contains(meta, "phase=target") {
				targetPhase = true
				health.TargetPhaseObserved = true
				sawSuspiciousOutbound = false
				lastSuspicious = observedConnection{}
			}
			emit(report.Finding{Severity: report.SeverityInfo, Type: "runtime", ReasonCode: "RUNTIME_METADATA", Path: "sandbox", Confidence: 90, Evidence: meta})
			continue
		}
		if strings.Contains(line, "GOAUDIT_TARGET_EXIT:") || strings.Contains(line, "GOAUDIT_PROBE_EXIT:") {
			isProbeExit := strings.Contains(line, "GOAUDIT_PROBE_EXIT:")
			marker := "GOAUDIT_TARGET_EXIT:"
			if isProbeExit {
				marker = "GOAUDIT_PROBE_EXIT:"
			}
			raw := strings.TrimSpace(line[strings.Index(line, marker)+len(marker):])
			code, err := strconv.Atoi(raw)
			if err != nil {
				continue
			}
			if isProbeExit {
				health.ProbeExitObserved = true
				health.ProbeExitCode = code
			} else {
				health.TargetExitObserved = true
				health.TargetExitCode = code
			}
			if code != 0 {
				rc := "TARGET_COMMAND_FAILED"
				evidence := "Target command returned non-zero exit status in sandbox"
				if isProbeExit {
					rc = "PROBE_COMMAND_FAILED"
					evidence = "Runtime probe returned non-zero exit status in sandbox"
				}
				if code == 127 {
					if isProbeExit {
						rc = "PROBE_COMMAND_NOT_FOUND"
					} else {
						rc = "TARGET_COMMAND_NOT_FOUND"
					}
				} else if code == 124 {
					if isProbeExit {
						rc = "PROBE_COMMAND_TIMEOUT"
					} else {
						rc = "TARGET_COMMAND_TIMEOUT"
					}
				}
				emit(report.Finding{Severity: report.SeverityWarning, Type: "runtime", ReasonCode: rc, Path: strconv.Itoa(code), Confidence: 95, Evidence: evidence})
			}
			continue
		}

		if targetPhase && isTraceSyscallLine(line) {
			if probePhase {
				health.ProbeSyscallObserved = true
			} else {
				health.TargetSyscallObserved = true
			}
		}

		// --- /proc/self/environ theft ---
		if procEnvironRegex.MatchString(line) {
			key := "ENV_THEFT:" + phaseTag(probePhase, targetPhase)
			if !seen[key] {
				seen[key] = true
				emit(report.Finding{Severity: report.SeverityCritical, Type: "fs_read", ReasonCode: "ENV_THEFT", Path: "/proc/self/environ", Confidence: 95, Evidence: "Read /proc/self/environ to steal CI secrets and environment variables"})
			}
			continue
		}

		// --- File Access ---
		if path, flags, ok := parseOpenPathFlags(line); ok {
			failed := strings.Contains(line, "= -1 ")
			isWrite := strings.Contains(flags, "O_WRONLY") || strings.Contains(flags, "O_RDWR") || strings.Contains(flags, "O_CREAT")

			if !isWrite {
				if failed {
					continue
				}
				if readCriticalPaths.MatchString(path) {
					key := "CREDENTIAL_READ:" + path + ":" + phaseTag(probePhase, targetPhase)
					if !seen[key] {
						seen[key] = true
						emit(report.Finding{Severity: report.SeverityCritical, Type: "fs_read", ReasonCode: "CREDENTIAL_READ", Path: path, Confidence: 95})
					}
				}
			} else {
				if writeCriticalPaths.MatchString(path) {
					key := "PERSISTENCE_WRITE:" + path + ":" + phaseTag(probePhase, targetPhase)
					if !seen[key] {
						seen[key] = true
						confidence := 95
						evidence := ""
						if failed {
							confidence = 85
							evidence = "Attempted write to sensitive persistence path failed in sandbox"
						}
						emit(report.Finding{Severity: report.SeverityCritical, Type: "fs_write", ReasonCode: "PERSISTENCE_WRITE", Path: path, Confidence: confidence, Evidence: evidence})
					}
				} else if !failed && !writeAllowedPaths.MatchString(path) {
					key := "UNEXPECTED_WRITE:" + path + ":" + phaseTag(probePhase, targetPhase)
					if !seen[key] {
						seen[key] = true
						emit(report.Finding{Severity: report.SeverityWarning, Type: "fs_write", ReasonCode: "UNEXPECTED_WRITE", Path: path, Confidence: 70})
					}
				}
			}
			continue
		}

		// --- Exec ---
		if execMatches := execRegex.FindStringSubmatch(line); len(execMatches) > 2 {
			// Skip failed syscalls.
			if strings.Contains(line, "= -1 ") {
				continue
			}
			bin := execMatches[1]
			args := execMatches[2]
			argsLower := strings.ToLower(args)
			if strings.HasSuffix(bin, "/crontab") || bin == "crontab" || (isShellBinary(bin) && strings.Contains(argsLower, "crontab")) {
				key := "PERSISTENCE_WRITE:crontab:" + phaseTag(probePhase, targetPhase)
				if !seen[key] {
					seen[key] = true
					evidence := "Crontab command executed from sandboxed install"
					if isShellBinary(bin) {
						evidence = "Shell invoked crontab persistence command"
					}
					emit(report.Finding{Severity: report.SeverityCritical, Type: "fs_write", ReasonCode: "PERSISTENCE_WRITE", Path: bin + " " + args, Confidence: 90, Evidence: evidence})
				}
				continue
			}
			isCritical := false
			if execSuspiciousBinaries.MatchString(bin) {
				isCritical = true
			} else if isShellBinary(bin) && (strings.Contains(args, "-i") || strings.Contains(args, "/dev/tcp")) {
				isCritical = true
			}
			if isCritical {
				key := "SUSPICIOUS_EXEC:" + bin + ":" + phaseTag(probePhase, targetPhase)
				if !seen[key] {
					seen[key] = true
					emit(report.Finding{Severity: report.SeverityCritical, Type: "exec", ReasonCode: "SUSPICIOUS_EXEC", Path: bin + " " + args, Confidence: 90})
				}
			}
			continue
		}

		// --- Mutation ---
		if mutMatches := mutRegex.FindStringSubmatch(line); len(mutMatches) > 1 {
			// Skip failed syscalls.
			if strings.Contains(line, "= -1 ") {
				continue
			}
			path := mutMatches[1]
			if path != "" && writeCriticalPaths.MatchString(path) {
				key := "PERSISTENCE_WRITE:" + path + ":" + phaseTag(probePhase, targetPhase)
				if !seen[key] {
					seen[key] = true
					emit(report.Finding{Severity: report.SeverityCritical, Type: "fs_write", ReasonCode: "PERSISTENCE_WRITE", Path: path, Confidence: 90})
				}
			}
			continue
		}

		// --- Privilege escalation ---
		if privMatches := privRegex.FindStringSubmatch(line); len(privMatches) > 2 {
			syscall := strings.ToLower(strings.TrimSpace(privMatches[1]))
			args := strings.Split(privMatches[2], ",")
			for i := range args {
				args[i] = strings.TrimSpace(args[i])
			}
			isRootEscalation := false
			switch syscall {
			case "setuid", "setgid":
				isRootEscalation = len(args) >= 1 && args[0] == "0"
			case "setreuid", "setregid":
				isRootEscalation = len(args) >= 2 && args[0] == "0" && args[1] == "0"
			}
			if isRootEscalation && targetPhase && strings.Contains(line, "= 0") {
				key := "PRIVILEGE_ESCALATION:" + phaseTag(probePhase, targetPhase)
				if !seen[key] {
					seen[key] = true
					emit(report.Finding{Severity: report.SeverityCritical, Type: "privilege", ReasonCode: "PRIVILEGE_ESCALATION", Path: line, Confidence: 92})
				}
			}
			continue
		}

		// --- Symlink ---
		if symlinkMatches := symlinkRegex.FindStringSubmatch(line); len(symlinkMatches) > 2 {
			target := symlinkMatches[1]
			linkPath := symlinkMatches[2]
			if readCriticalPaths.MatchString(target) || writeCriticalPaths.MatchString(target) ||
				readCriticalPaths.MatchString(linkPath) || writeCriticalPaths.MatchString(linkPath) {
				emit(report.Finding{Severity: report.SeverityCritical, Type: "fs_write", ReasonCode: "SYMLINK_SENSITIVE_PATH", Path: linkPath + " -> " + target, Confidence: 90, Evidence: "Symlink created targeting a sensitive file path"})
			}
			continue
		}

		// --- memfd_create ---
		if memfdRegex.MatchString(line) {
			name := ""
			if m := memfdRegex.FindStringSubmatch(line); len(m) > 1 {
				name = m[1]
			}
			emit(report.Finding{Severity: report.SeverityCritical, Type: "exec", ReasonCode: "FILELESS_EXEC", Path: name, Confidence: 92, Evidence: "memfd_create detected — possible fileless code execution"})
			continue
		}

		// --- ptrace ---
		if ptraceAttachRegex.MatchString(line) {
			emit(report.Finding{Severity: report.SeverityCritical, Type: "exec", ReasonCode: "PROCESS_INJECTION", Path: line, Confidence: 95, Evidence: "ptrace ATTACH/SEIZE detected — possible process injection"})
			continue
		}

		// --- bind/listen ---
		if blMatches := bindListenRegex.FindStringSubmatch(line); len(blMatches) > 1 {
			port, _ := strconv.Atoi(blMatches[1])
			if port > 0 {
				emit(report.Finding{Severity: report.SeverityWarning, Type: "network", ReasonCode: "BACKDOOR_LISTENER", Port: port, Confidence: 80, Evidence: "Process binding/listening on a network port inside sandbox"})
			}
			continue
		}

		// --- Network send after suspicious outbound connect ---
		if sendFD, ok := parseSendFD(line); ok && targetPhase {
			conn, matchedFD := suspiciousByFD[sendFD]
			if !matchedFD && sawSuspiciousOutbound {
				conn = lastSuspicious
			}
			if !matchedFD && !sawSuspiciousOutbound {
				continue
			}
			key := "DATA_EXFIL_SEND:" + conn.IP + ":" + strconv.Itoa(conn.Port) + ":" + phaseTag(probePhase, targetPhase)
			if !seen[key] {
				seen[key] = true
				host := conn.Host
				if host == "" {
					host = "outbound"
				}
				emit(report.Finding{Severity: report.SeverityCritical, Type: "network", ReasonCode: "DATA_EXFIL", Path: host, Host: host, IP: conn.IP, Port: conn.Port, Confidence: 88, Evidence: "Observed network data send after connection to a non-registry host"})
			}
			continue
		}

		// --- Network connections ---
		if netMatches := netRegex.FindStringSubmatch(line); len(netMatches) > 2 {
			port, _ := strconv.Atoi(netMatches[1])
			if port == 0 {
				continue
			}
			ipStr := netMatches[2]
			if ipStr == "" && len(netMatches) > 3 {
				ipStr = netMatches[3]
			}
			if ipStr == "" {
				continue
			}
			ip := net.ParseIP(ipStr)
			if ip != nil && (ip.IsLoopback() || ip.String() == "127.0.0.1" || ip.String() == "::1") {
				continue
			}
			// Skip DNS resolver connections (port 53) — normal system behavior.
			if port == 53 {
				continue
			}
			// Deduplicate by IP:Port and phase
			dedupKey := fmt.Sprintf("NET:%s:%d:%s", ipStr, port, phaseTag(probePhase, targetPhase))
			if seen[dedupKey] {
				continue
			}
			seen[dedupKey] = true

			// Classify: known registry or unknown host
			host := ipStr
			reasonCode := "EXTERNAL_NETWORK"
			severity := report.SeverityWarning

			if registryHost, ok := opts.KnownRegistryIPs[ipStr]; ok {
				host = registryHost
				reasonCode = "EXTERNAL_NETWORK_REGISTRY"
				severity = report.SeverityInfo
				sawSuspiciousOutbound = false
			} else if ipStr == "169.254.169.254" {
				host = "cloud metadata service"
				reasonCode = "CLOUD_METADATA_ACCESS"
				severity = report.SeverityCritical
				sawSuspiciousOutbound = true
			} else if ip != nil && (ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
				reasonCode = "INTERNAL_NETWORK"
				severity = report.SeverityWarning
				sawSuspiciousOutbound = true
			} else {
				sawSuspiciousOutbound = true
				if names, err := net.LookupAddr(ipStr); err == nil && len(names) > 0 {
					host = strings.TrimSuffix(names[0], ".")
				}
			}
			fd := parseConnectFD(line)
			if sawSuspiciousOutbound && reasonCode != "EXTERNAL_NETWORK_REGISTRY" {
				lastSuspicious = observedConnection{Host: host, IP: ipStr, Port: port}
				if fd != "" {
					suspiciousByFD[fd] = lastSuspicious
				}
			}

			emit(report.Finding{Severity: severity, Type: "network", ReasonCode: reasonCode, Host: host, Port: port, IP: ipStr, Confidence: 60})
		}
	}

	findings = finalizeDynamicFindings(findings)
	return findings, health, scanner.Err()
}

func parseOpenPathFlags(line string) (string, string, bool) {
	matches := fsRegex.FindStringSubmatch(line)
	if len(matches) > 2 {
		return matches[1], matches[2], true
	}
	if !(strings.Contains(line, "open(") || strings.Contains(line, "openat(") || strings.Contains(line, "openat2(")) {
		return "", "", false
	}
	first := strings.Index(line, "\"")
	if first < 0 {
		return "", "", false
	}
	secondRel := strings.Index(line[first+1:], "\"")
	if secondRel < 0 {
		return "", "", false
	}
	second := first + 1 + secondRel
	path := line[first+1 : second]
	rest := line[second+1:]
	if idx := strings.Index(rest, "{flags="); idx >= 0 {
		rest = rest[idx+len("{flags="):]
	} else if idx := strings.Index(rest, ","); idx >= 0 {
		rest = rest[idx+1:]
	}
	rest = strings.TrimSpace(rest)
	end := len(rest)
	for i, r := range rest {
		if !(r == '_' || r == '|' || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			end = i
			break
		}
	}
	flags := rest[:end]
	if path == "" || flags == "" {
		return "", "", false
	}
	return path, flags, true
}

func parseConnectFD(line string) string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "connect(") {
		return ""
	}
	rest := strings.TrimPrefix(line, "connect(")
	idx := strings.Index(rest, ",")
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:idx])
}

func parseSendFD(line string) (string, bool) {
	line = strings.TrimSpace(line)
	prefix := ""
	if strings.HasPrefix(line, "sendto(") {
		prefix = "sendto("
	} else if strings.HasPrefix(line, "sendmsg(") {
		prefix = "sendmsg("
	} else {
		return "", false
	}
	rest := strings.TrimPrefix(line, prefix)
	idx := strings.Index(rest, ",")
	if idx < 0 {
		return "", false
	}
	fd := strings.TrimSpace(rest[:idx])
	return fd, fd != ""
}

func phaseTag(probePhase, targetPhase bool) string {
	if !targetPhase {
		return ""
	}
	if probePhase {
		return "[runtime probe]"
	}
	return "[install]"
}

func appendPhaseEvidence(evidence, tag string) string {
	evidence = strings.TrimSpace(evidence)
	if evidence == "" {
		return tag
	}
	if strings.Contains(evidence, tag) {
		return evidence
	}
	return evidence + " " + tag
}

func phaseFromEvidence(evidence string) string {
	if strings.Contains(evidence, "[runtime probe]") {
		return "[runtime probe]"
	}
	if strings.Contains(evidence, "[install]") {
		return "[install]"
	}
	return ""
}

func isShellBinary(bin string) bool {
	return strings.HasSuffix(bin, "/bash") ||
		strings.HasSuffix(bin, "/sh") ||
		strings.HasSuffix(bin, "/dash") ||
		bin == "bash" ||
		bin == "sh" ||
		bin == "dash"
}

func finalizeDynamicFindings(findings []report.Finding) []report.Finding {
	hasCredentialTheft := false
	for _, f := range findings {
		switch f.ReasonCode {
		case "CREDENTIAL_READ", "ENV_THEFT":
			hasCredentialTheft = true
		}
	}

	out := make([]report.Finding, 0, len(findings))
	seenExfil := map[string]bool{}
	for _, f := range findings {
		if f.ReasonCode == "DATA_EXFIL" {
			phase := phaseFromEvidence(f.Evidence)
			seenExfil[f.IP+":"+strconv.Itoa(f.Port)+":"+phase] = true
			seenExfil["phase:"+phase] = true
		}
	}
	for _, f := range findings {
		if hasCredentialTheft && (f.ReasonCode == "EXTERNAL_NETWORK" || f.ReasonCode == "INTERNAL_NETWORK") {
			phase := phaseFromEvidence(f.Evidence)
			key := f.IP + ":" + strconv.Itoa(f.Port) + ":" + phase
			if seenExfil[key] || seenExfil["phase:"+phase] {
				continue
			}
			seenExfil[key] = true
			seenExfil["phase:"+phase] = true
			out = append(out, report.Finding{
				Severity:   report.SeverityCritical,
				Type:       f.Type,
				ReasonCode: "DATA_EXFIL",
				Path:       f.Host,
				Host:       f.Host,
				Port:       f.Port,
				IP:         f.IP,
				Confidence: 90,
				Evidence:   appendPhaseEvidence("Outbound connection to non-registry host after credential access was observed", f.Evidence),
			})
			continue
		}
		out = append(out, f)
	}
	return out
}

func isTraceSyscallLine(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	if strings.Contains(line, "GOAUDIT_") {
		return false
	}
	if idx := strings.Index(line, "("); idx > 0 {
		name := line[:idx]
		fields := strings.Fields(name)
		if len(fields) > 0 {
			name = fields[len(fields)-1]
		}
		if name == "" {
			return false
		}
		for _, r := range name {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
				continue
			}
			return false
		}
		return true
	}
	return false
}
