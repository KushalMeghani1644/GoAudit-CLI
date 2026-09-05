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
	// Word boundary avoids matching "link(" inside "symlink(".
	mutRegex             = regexp.MustCompile(`(?i)\b(?:chmod|fchmod|fchmodat|rename|renameat|renameat2|link|linkat|mkdir|mkdirat|unlink|unlinkat|truncate|ftruncate|chown|fchown|lchown|fchownat)\(`)
	mountRegex           = regexp.MustCompile(`(?i)\b(?:mount|umount2)\(`)
	capsetRegex          = regexp.MustCompile(`(?i)\bcapset\(`)
	privRegex            = regexp.MustCompile(`(?i)(setuid|setgid|seteuid|setegid|setreuid|setregid|setresuid|setresgid|setfsuid|setfsgid|setgroups)\(([^)]*)\)`)
	chmodRegex           = regexp.MustCompile(`(?i)(?:chmod|fchmodat)\([^"]*"?([^",)]*)"?\s*,\s*0?([0-7]{3,4})`)
	fchmodRegex          = regexp.MustCompile(`(?i)\bfchmod\(\s*(\d+)\s*,\s*0?([0-7]{3,4})`)
	kernelPrivilegeRegex = regexp.MustCompile(`(?i)\b(unshare|setns|clone|chroot|keyctl|bpf)\(`)
	namespaceFlagRegex   = regexp.MustCompile(`(?i)\bCLONE_NEW(?:CGROUP|IPC|NET|NS|PID|TIME|USER|UTS)\b`)
	keyctlPrivilegeRegex = regexp.MustCompile(`(?i)\bKEYCTL_(?:CHOWN|SETPERM|RESTRICT_KEYRING)\b`)
	bpfPrivilegeRegex    = regexp.MustCompile(`(?i)\bBPF_(?:PROG_LOAD|PROG_ATTACH|PROG_DETACH|RAW_TRACEPOINT_OPEN|LINK_CREATE|LINK_UPDATE|BTF_LOAD|TOKEN_CREATE)\b`)

	readCriticalPaths  = regexp.MustCompile(`(?i)((?:^|.*?/)\.env(?:\b|$)|.*?/\.ssh/.*?|.*?/\.aws/.*?|.*?/\.kube/.*?|.*?/\.git-credentials|.*?/\.npmrc|.*?id_rsa|^/etc/shadow$)`)
	writeCriticalPaths = regexp.MustCompile(`(?i)(.*?/\.bashrc|.*?/\.zshrc|.*?/\.profile|.*?/\.ssh/authorized_keys|^/etc/crontab|^/etc/cron\..*|^/usr/local/bin/.*|^/usr/bin/.*|^/etc/passwd$|^/etc/shadow$)`)
	writeAllowedPaths  = regexp.MustCompile(`(?i)(^/tmp/|^/dev/|^/proc/|^/sys/|^/workspace/|node_modules/|\.npm/|\.cache/|site-packages/|/var/tmp/|/pnpm/store/|pnpm-state\.json|^/usr/local/lib/|^/usr/lib/|(^|/)package(-lock)?\.json$|(^|/)pnpm-lock\.yaml$|(^|/)bun\.lockb?$|\.hm$|^/root/\.config/|^/home/.*?/\.config/|^/root/\.local/|^/home/.*?/\.local/|^/root/\.bun/|^/home/.*?/\.bun/)`)

	execSuspiciousBinaries = regexp.MustCompile(`(?i)(.*?/nc$|.*?/ncat$|.*?/netcat$|^/tmp/.*)`)

	symlinkRegex      = regexp.MustCompile(`(?i)(?:symlink|symlinkat)\("(.*?)",\s*(?:\d+,\s*)?"(.*?)"`)
	memfdRegex        = regexp.MustCompile(`(?i)memfd_create\("(.*?)"`)
	ptraceAttachRegex = regexp.MustCompile(`(?i)ptrace\(PTRACE_(?:ATTACH|SEIZE)`)
	bindListenRegex   = regexp.MustCompile(`(?:bind|listen)\(\d+,\s*\{sa_family=AF_INET6?,\s*sin6?_port=htons\((\d+)\)`)

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

	// RunAsRoot marks findings whose success may only reflect the scanner's
	// deliberately privileged execution context.
	RunAsRoot bool
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
		if opts.RunAsRoot && f.Type == "privilege" {
			// A successful transition to ID 0 while the scanner already runs as
			// root does not demonstrate that the package escalated privileges.
			if f.ReasonCode == "PRIVILEGE_ESCALATION" {
				f.ReasonCode = "PRIVILEGE_ESCALATION_ATTEMPT"
				f.Severity = report.SeverityWarning
			}
			f.Evidence = appendEvidence(f.Evidence, "Root scan: successful privileged operations may be scanner-induced and are not proof of escalation")
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
		if strings.Contains(line, "GOAUDIT_PROBE_LIMITATION") {
			key := "PROBE_LIMITATION"
			if !seen[key] {
				seen[key] = true
				emit(report.Finding{Severity: report.SeverityInfo, Type: "runtime", ReasonCode: "PROBE_LIMITATION", Path: "probe", Confidence: 90, Evidence: "Runtime probe covers package import/require and optional bin --help only"})
			}
			continue
		}
		if strings.Contains(line, "GOAUDIT_RUNTIME_META:") {
			meta := strings.TrimSpace(line[strings.Index(line, "GOAUDIT_RUNTIME_META:")+len("GOAUDIT_RUNTIME_META:"):])
			if strings.Contains(meta, "phase=probe") {
				probePhase = true
				targetPhase = true
				health.ProbePhaseObserved = true
				suspiciousByFD = map[string]observedConnection{}
			}
			if strings.Contains(meta, "phase=target") {
				targetPhase = true
				health.TargetPhaseObserved = true
				suspiciousByFD = map[string]observedConnection{}
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
			if isAccountFile(path) {
				// O_RDONLY of /etc/passwd is normal NSS/account lookup (runuser, getent,
				// libc). Flagging it causes scanner-induced false positives on every
				// non-root scan. Only writes to passwd and any access to shadow matter.
				if path == "/etc/passwd" && !isWrite {
					continue
				}
				key := "ACCOUNT_FILE_ACCESS:" + path + ":" + phaseTag(probePhase, targetPhase)
				if !seen[key] {
					seen[key] = true
					confidence := 92
					severity := report.SeverityCritical
					evidence := "Accessed Unix account database file"
					if failed {
						confidence = 78
						severity = report.SeverityWarning
						evidence = "Attempted to access Unix account database file failed in sandbox"
					}
					emit(report.Finding{Severity: severity, Type: "privilege", ReasonCode: "ACCOUNT_FILE_ACCESS", Path: path, Confidence: confidence, Evidence: evidence})
				}
				continue
			}

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
			bin := execMatches[1]
			args := execMatches[2]
			argsLower := strings.ToLower(args)
			if f, ok := privilegeExecFinding(bin, args, strings.Contains(line, "= -1 ")); ok {
				key := f.ReasonCode + ":" + f.Path + ":" + phaseTag(probePhase, targetPhase)
				if !seen[key] {
					seen[key] = true
					emit(f)
				}
				continue
			}
			// Skip other failed exec syscalls.
			if strings.Contains(line, "= -1 ") {
				continue
			}
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
		if mutRegex.MatchString(line) {
			if path, mode, ok := parseChmodModePath(line); ok && hasSUIDOrSGIDBit(mode) {
				key := "SUID_SGID_BIT_SET:" + path + ":" + mode + ":" + phaseTag(probePhase, targetPhase)
				if !seen[key] {
					seen[key] = true
					confidence := 90
					severity := report.SeverityCritical
					evidence := "Set SUID/SGID permission bits on executable path"
					if strings.Contains(line, "= -1 ") {
						confidence = 78
						severity = report.SeverityWarning
						evidence = "Attempted to set SUID/SGID permission bits failed in sandbox"
					}
					emit(report.Finding{Severity: severity, Type: "privilege", ReasonCode: "SUID_SGID_BIT_SET", Path: path + " mode " + mode, Confidence: confidence, Evidence: evidence})
				}
				continue
			}
			// Skip failed syscalls.
			if strings.Contains(line, "= -1 ") {
				continue
			}
			// chown of sensitive paths is persistence / ownership takeover signal.
			if strings.Contains(strings.ToLower(line), "chown") {
				for _, path := range extractQuotedPaths(line) {
					if path == "" || !writeCriticalPaths.MatchString(path) {
						continue
					}
					key := "OWNERSHIP_CHANGE:" + path + ":" + phaseTag(probePhase, targetPhase)
					if !seen[key] {
						seen[key] = true
						emit(report.Finding{Severity: report.SeverityCritical, Type: "privilege", ReasonCode: "OWNERSHIP_CHANGE", Path: path, Confidence: 88, Evidence: "Changed ownership of a sensitive path"})
					}
				}
				// Still also evaluate for PERSISTENCE_WRITE below when path matches.
			}
			// Check all path arguments so rename("/tmp/x", "/etc/cron.d/x") flags the destination.
			// Also covers truncate of critical paths.
			for _, path := range extractQuotedPaths(line) {
				if path == "" || !writeCriticalPaths.MatchString(path) {
					continue
				}
				key := "PERSISTENCE_WRITE:" + path + ":" + phaseTag(probePhase, targetPhase)
				if !seen[key] {
					seen[key] = true
					emit(report.Finding{Severity: report.SeverityCritical, Type: "fs_write", ReasonCode: "PERSISTENCE_WRITE", Path: path, Confidence: 90})
				}
			}
			continue
		}

		// --- mount / umount2 ---
		if mountRegex.MatchString(line) {
			if strings.Contains(line, "= -1 ") {
				key := "MOUNT_ATTEMPT:" + phaseTag(probePhase, targetPhase)
				if !seen[key] {
					seen[key] = true
					emit(report.Finding{Severity: report.SeverityWarning, Type: "privilege", ReasonCode: "MOUNT_OPERATION_ATTEMPT", Path: line, Confidence: 75, Evidence: "Attempted mount/umount failed in sandbox"})
				}
			} else {
				key := "MOUNT_OP:" + phaseTag(probePhase, targetPhase)
				if !seen[key] {
					seen[key] = true
					emit(report.Finding{Severity: report.SeverityCritical, Type: "privilege", ReasonCode: "MOUNT_OPERATION", Path: line, Confidence: 92, Evidence: "Performed mount/umount inside the sandbox"})
				}
			}
			continue
		}

		// --- namespace and privileged kernel operations ---
		if matches := kernelPrivilegeRegex.FindStringSubmatch(line); len(matches) > 1 {
			syscall := strings.ToLower(matches[1])
			if isPrivilegeRelevantKernelOperation(syscall, line) {
				failed := strings.Contains(line, "= -1 ")
				reason := "PRIVILEGED_KERNEL_OPERATION"
				severity := report.SeverityCritical
				confidence := 90
				evidence := "Performed privilege-relevant kernel operation: " + syscall
				if failed {
					reason = "PRIVILEGED_KERNEL_OPERATION_ATTEMPT"
					severity = report.SeverityWarning
					confidence = 75
					evidence = "Privilege-relevant kernel operation failed in sandbox: " + syscall
				}
				key := reason + ":" + syscall + ":" + phaseTag(probePhase, targetPhase)
				if !seen[key] {
					seen[key] = true
					emit(report.Finding{Severity: severity, Type: "privilege", ReasonCode: reason, Path: line, Confidence: confidence, Evidence: evidence})
				}
			}
			continue
		}

		// --- capset ---
		// capset can raise, retain, drop, or clear capabilities. A syscall trace
		// has no prior capability set, so even a non-zero result cannot prove an
		// increase. Keep this as a neutral capability-change warning.
		if capsetRegex.MatchString(line) {
			failed := strings.Contains(line, "= -1 ")
			key := "CAPSET:" + phaseTag(probePhase, targetPhase)
			if !seen[key] {
				seen[key] = true
				conf := 70
				ev := "capset used to modify process capabilities without a proven increase"
				if failed {
					conf = 60
					ev = "capset capability change failed in sandbox"
				}
				emit(report.Finding{Severity: report.SeverityWarning, Type: "privilege", ReasonCode: "CAPABILITY_CHANGE", Path: line, Confidence: conf, Evidence: ev})
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
			case "setuid", "setgid", "seteuid", "setegid":
				isRootEscalation = len(args) >= 1 && isRootNumericArg(args[0])
			case "setreuid", "setregid":
				isRootEscalation = len(args) >= 2 && isRootNumericArg(args[1])
			case "setresuid", "setresgid":
				isRootEscalation = len(args) >= 3 && (isRootNumericArg(args[0]) || isRootNumericArg(args[1]) || isRootNumericArg(args[2]))
			case "setfsuid", "setfsgid":
				// These calls return the previous filesystem ID rather than a
				// success code, so the trace proves an attempt but not success.
				if len(args) >= 1 && isRootNumericArg(args[0]) && targetPhase {
					key := "PRIVILEGE_ESCALATION_ATTEMPT:" + syscall + ":" + strings.Join(args, ",") + ":" + phaseTag(probePhase, targetPhase)
					if !seen[key] {
						seen[key] = true
						emit(report.Finding{Severity: report.SeverityWarning, Type: "privilege", ReasonCode: "PRIVILEGE_ESCALATION_ATTEMPT", Path: line, Confidence: 75, Evidence: "Attempted root filesystem UID/GID transition; syscall return value is the previous ID"})
					}
				}
				continue
			case "setgroups":
				for _, arg := range args {
					if isRootNumericArg(arg) {
						isRootEscalation = true
						break
					}
				}
			}
			if isRootEscalation && targetPhase && strings.Contains(line, "= 0") {
				key := "PRIVILEGE_ESCALATION:" + syscall + ":" + strings.Join(args, ",") + ":" + phaseTag(probePhase, targetPhase)
				if !seen[key] {
					seen[key] = true
					emit(report.Finding{Severity: report.SeverityCritical, Type: "privilege", ReasonCode: "PRIVILEGE_ESCALATION", Path: line, Confidence: 92})
				}
			} else if isRootEscalation && targetPhase && strings.Contains(line, "= -1") {
				key := "PRIVILEGE_ESCALATION_ATTEMPT:" + syscall + ":" + strings.Join(args, ",") + ":" + phaseTag(probePhase, targetPhase)
				if !seen[key] {
					seen[key] = true
					emit(report.Finding{Severity: report.SeverityWarning, Type: "privilege", ReasonCode: "PRIVILEGE_ESCALATION_ATTEMPT", Path: line, Confidence: 75, Evidence: "Attempted root UID/GID transition failed in sandbox"})
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

		// A closed descriptor can be reused for an unrelated connection. Drop its
		// prior association only once close succeeds.
		if fd, ok := parseCloseFD(line); ok {
			delete(suspiciousByFD, fd)
			continue
		}

		// --- Network send after suspicious outbound connect ---
		// Require a successful positive-byte send on the FD that was previously
		// connected to a suspicious host. Do not fall back to lastSuspicious for
		// unrelated or failed send-like syscalls.
		if sendFD, ok := parseSendFD(line); ok && targetPhase {
			conn, matchedFD := suspiciousByFD[sendFD]
			if !matchedFD {
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
			} else if ipStr == "169.254.169.254" {
				host = "cloud metadata service"
				reasonCode = "CLOUD_METADATA_ACCESS"
				severity = report.SeverityCritical
			} else if ip != nil && (ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
				reasonCode = "INTERNAL_NETWORK"
				severity = report.SeverityWarning
			} else {
				if names, err := net.LookupAddr(ipStr); err == nil && len(names) > 0 {
					host = strings.TrimSuffix(names[0], ".")
				}
			}
			fd := parseConnectFD(line)
			// A failed connect does not establish an output FD. A successful
			// registry connect or a successful close must also clear any stale
			// non-registry association before that FD can be reused.
			if result, ok := parseSyscallResult(line); ok && result == 0 && fd != "" {
				if reasonCode == "EXTERNAL_NETWORK_REGISTRY" {
					delete(suspiciousByFD, fd)
				} else {
					suspiciousByFD[fd] = observedConnection{Host: host, IP: ipStr, Port: port}
				}
			}

			emit(report.Finding{Severity: severity, Type: "network", ReasonCode: reasonCode, Host: host, Port: port, IP: ipStr, Confidence: 60})
		}
	}

	findings = finalizeDynamicFindings(findings)
	return findings, health, scanner.Err()
}

func isPrivilegeRelevantKernelOperation(syscall, line string) bool {
	switch syscall {
	case "clone", "unshare":
		// Process creation and per-process resource isolation (for example,
		// CLONE_FILES) are routine. Creating a kernel namespace is the
		// privilege-relevant operation.
		return namespaceFlagRegex.MatchString(line)
	case "keyctl":
		// Joining/creating a session keyring is available to ordinary callers.
		// Retain operations that alter key ownership or access controls.
		return keyctlPrivilegeRegex.MatchString(line)
	case "bpf":
		// Map reads/writes and object queries are routine uses of an existing
		// BPF object; loading or attaching kernel code is privilege-relevant.
		return bpfPrivilegeRegex.MatchString(line)
	case "setns", "chroot":
		return true
	default:
		return false
	}
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

func parseCloseFD(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "close(") {
		return "", false
	}
	result, ok := parseSyscallResult(line)
	if !ok || result != 0 {
		return "", false
	}
	rest := strings.TrimPrefix(line, "close(")
	idx := strings.Index(rest, ")")
	if idx < 0 {
		return "", false
	}
	fd := strings.TrimSpace(rest[:idx])
	return fd, fd != ""
}

func parseSendFD(line string) (string, bool) {
	line = strings.TrimSpace(line)
	// Only successful transfers with a positive result count as exfil evidence.
	// Failed (= -1) and zero-byte (= 0) sends must not produce DATA_EXFIL.
	if result, ok := parseSyscallResult(line); !ok || result <= 0 {
		return "", false
	}

	prefix := ""
	isSplice := false
	switch {
	case strings.HasPrefix(line, "sendto("):
		prefix = "sendto("
	case strings.HasPrefix(line, "sendmsg("):
		prefix = "sendmsg("
	case strings.HasPrefix(line, "sendmmsg("):
		prefix = "sendmmsg("
	case strings.HasPrefix(line, "sendfile("):
		// sendfile(out_fd, in_fd, ...) — out_fd is the network destination side.
		prefix = "sendfile("
	case strings.HasPrefix(line, "splice("):
		// splice(fd_in, off_in, fd_out, ...) — fd_out is the destination side.
		prefix = "splice("
		isSplice = true
	default:
		return "", false
	}
	rest := strings.TrimPrefix(line, prefix)
	if isSplice {
		fd, ok := nthCSVArg(rest, 2)
		return fd, ok && fd != ""
	}
	idx := strings.Index(rest, ",")
	if idx < 0 {
		return "", false
	}
	fd := strings.TrimSpace(rest[:idx])
	return fd, fd != ""
}

// parseSyscallResult extracts the integer return value from an strace line
// ending in ") = N" or ") = -1 ERRNO (...)".
func parseSyscallResult(line string) (int64, bool) {
	idx := strings.LastIndex(line, ") = ")
	if idx < 0 {
		return 0, false
	}
	rest := strings.TrimSpace(line[idx+len(") = "):])
	if rest == "" {
		return 0, false
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// nthCSVArg returns the n-th comma-separated top-level argument from an strace
// argument list (0-based), ignoring commas inside nested parentheses.
func nthCSVArg(args string, n int) (string, bool) {
	depth := 0
	start := 0
	argi := 0
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case '(':
			depth++
		case ')':
			if depth == 0 {
				// End of syscall args.
				if argi == n {
					return strings.TrimSpace(args[start:i]), true
				}
				return "", false
			}
			depth--
		case ',':
			if depth != 0 {
				continue
			}
			if argi == n {
				return strings.TrimSpace(args[start:i]), true
			}
			argi++
			start = i + 1
		}
	}
	if argi == n {
		return strings.TrimSpace(args[start:]), true
	}
	return "", false
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

func appendEvidence(evidence, detail string) string {
	if evidence == "" {
		return detail
	}
	return evidence + "; " + detail
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

func isAccountFile(path string) bool {
	return path == "/etc/passwd" || path == "/etc/shadow"
}

// extractQuotedPaths returns double-quoted path arguments from an strace line.
func extractQuotedPaths(line string) []string {
	var paths []string
	rest := line
	for {
		start := strings.Index(rest, "\"")
		if start < 0 {
			break
		}
		rest = rest[start+1:]
		end := strings.Index(rest, "\"")
		if end < 0 {
			break
		}
		paths = append(paths, rest[:end])
		rest = rest[end+1:]
	}
	return paths
}

func normalizeNumericArg(arg string) string {
	arg = strings.TrimSpace(arg)
	arg = strings.Trim(arg, "[]{}")
	if idx := strings.Index(arg, "/*"); idx >= 0 {
		arg = arg[:idx]
	}
	if idx := strings.Index(arg, " "); idx >= 0 {
		arg = arg[:idx]
	}
	return strings.TrimSpace(arg)
}

func isRootNumericArg(arg string) bool {
	return normalizeNumericArg(arg) == "0"
}

func parseChmodModePath(line string) (string, string, bool) {
	if match := fchmodRegex.FindStringSubmatch(line); len(match) == 3 {
		return "fd " + match[1], match[2], true
	}
	m := chmodRegex.FindStringSubmatch(line)
	if len(m) > 2 && m[1] != "" && m[2] != "" {
		return m[1], m[2], true
	}
	if !strings.Contains(line, "chmod(") && !strings.Contains(line, "fchmodat(") {
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
	parts := strings.Split(rest, ",")
	for _, part := range parts {
		mode := strings.TrimSpace(part)
		end := 0
		for end < len(mode) {
			c := mode[end]
			if c < '0' || c > '7' {
				break
			}
			end++
		}
		mode = mode[:end]
		if path != "" && len(mode) >= 3 {
			return path, mode, true
		}
	}
	return "", "", false
}

func hasSUIDOrSGIDBit(mode string) bool {
	mode = strings.TrimSpace(mode)
	if len(mode) < 4 {
		return false
	}
	special := mode[len(mode)-4]
	return special == '2' || special == '3' || special == '4' || special == '5' || special == '6' || special == '7'
}

func privilegeExecFinding(bin, args string, failed bool) (report.Finding, bool) {
	path := bin + " " + args
	argsLower := strings.ToLower(args)
	binBase := strings.ToLower(bin)
	if idx := strings.LastIndex(binBase, "/"); idx >= 0 {
		binBase = binBase[idx+1:]
	}
	combined := strings.ToLower(bin + " " + args)
	severity := report.SeverityCritical
	confidence := 88
	evidenceSuffix := ""
	if failed {
		severity = report.SeverityWarning
		confidence = 74
		evidenceSuffix = " failed in sandbox"
	}
	switch {
	case binBase == "sudo" || binBase == "su" || binBase == "pkexec" ||
		(isShellBinary(bin) && containsPrivilegeCommand(argsLower, "sudo", "su", "pkexec")):
		return report.Finding{Severity: severity, Type: "privilege", ReasonCode: "PRIVILEGE_ESCALATION_EXEC", Path: path, Confidence: confidence, Evidence: "Executed privilege escalation helper" + evidenceSuffix}, true
	case binBase == "setcap" || (isShellBinary(bin) && containsPrivilegeCommand(argsLower, "setcap")):
		return report.Finding{Severity: severity, Type: "privilege", ReasonCode: "CAPABILITY_ESCALATION", Path: path, Confidence: confidence, Evidence: "Attempted to grant Linux capabilities to an executable" + evidenceSuffix}, true
	case binBase == "unshare" || binBase == "nsenter" || (isShellBinary(bin) && containsPrivilegeCommand(argsLower, "unshare", "nsenter")):
		return report.Finding{Severity: severity, Type: "privilege", ReasonCode: "NAMESPACE_ESCAPE_ATTEMPT", Path: path, Confidence: confidence, Evidence: "Executed namespace manipulation command" + evidenceSuffix}, true
	case strings.Contains(combined, "ld_preload=") && (strings.Contains(combined, "/passwd") || strings.Contains(combined, " passwd")):
		return report.Finding{Severity: severity, Type: "privilege", ReasonCode: "LD_PRELOAD_PRIVILEGE_ATTEMPT", Path: path, Confidence: confidence, Evidence: "Attempted LD_PRELOAD injection against a privileged helper" + evidenceSuffix}, true
	case (binBase == "chmod" || isShellBinary(bin)) && containsSUIDChmod(argsLower):
		return report.Finding{Severity: severity, Type: "privilege", ReasonCode: "SUID_SGID_BIT_SET", Path: path, Confidence: confidence, Evidence: "Attempted to set SUID/SGID permission bits" + evidenceSuffix}, true
	}
	return report.Finding{}, false
}

func containsPrivilegeCommand(s string, commands ...string) bool {
	for _, cmd := range commands {
		if regexp.MustCompile(`(^|[^a-z0-9_./-])` + regexp.QuoteMeta(cmd) + `($|[^a-z0-9_/-])`).MatchString(s) {
			return true
		}
	}
	return false
}

func containsSUIDChmod(argsLower string) bool {
	if !strings.Contains(argsLower, "chmod") {
		return false
	}
	return strings.Contains(argsLower, " 4755") ||
		strings.Contains(argsLower, " 2755") ||
		strings.Contains(argsLower, " u+s") ||
		strings.Contains(argsLower, " g+s")
}

func finalizeDynamicFindings(findings []report.Finding) []report.Finding {
	// Existing DATA_EXFIL findings come from observed send after a suspicious
	// connect — those remain the only hard-exfil path. Index exact
	// destination/phase keys only (no phase-wide suppression).
	seenExfil := map[string]bool{}
	for _, f := range findings {
		if f.ReasonCode == "DATA_EXFIL" {
			phase := phaseFromEvidence(f.Evidence)
			seenExfil[f.IP+":"+strconv.Itoa(f.Port)+":"+phase] = true
		}
	}

	// Walk findings in event order. Correlate outbound network only with
	// credential access observed earlier in the same phase.
	credSeenByPhase := map[string]bool{}
	seenCorr := map[string]bool{}
	out := make([]report.Finding, 0, len(findings))
	for _, f := range findings {
		phase := phaseFromEvidence(f.Evidence)
		switch f.ReasonCode {
		case "CREDENTIAL_READ", "ENV_THEFT":
			credSeenByPhase[phase] = true
			out = append(out, f)
			continue
		}

		// Credential read + connect without observed send is correlative only.
		// Do not upgrade to hard-malicious DATA_EXFIL; emit a warning instead.
		if credSeenByPhase[phase] && (f.ReasonCode == "EXTERNAL_NETWORK" || f.ReasonCode == "INTERNAL_NETWORK") {
			exfilKey := f.IP + ":" + strconv.Itoa(f.Port) + ":" + phase
			// Suppress the raw network finding only for the exact destination
			// that already has proven DATA_EXFIL; keep unrelated outbound visible.
			if seenExfil[exfilKey] {
				continue
			}
			if !seenCorr[exfilKey] {
				seenCorr[exfilKey] = true
				out = append(out, report.Finding{
					Severity:   report.SeverityWarning,
					Type:       f.Type,
					ReasonCode: "CREDENTIAL_READ_WITH_OUTBOUND",
					Path:       f.Host,
					Host:       f.Host,
					Port:       f.Port,
					IP:         f.IP,
					Confidence: 70,
					Evidence:   appendPhaseEvidence("Outbound connection to non-registry host after credential access was observed (no data send proven)", f.Evidence),
				})
			}
			// Still keep the underlying network finding for visibility.
			out = append(out, f)
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
