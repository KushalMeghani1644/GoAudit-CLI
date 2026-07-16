package sandbox

import (
	"strings"
	"testing"
)

func TestHoneypotScript(t *testing.T) {
	script := honeypotScript()

	if !strings.Contains(script, "${SANDBOX_HOME}/.aws/credentials") {
		t.Error("honeypot missing aws credentials")
	}
	if !strings.Contains(script, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("honeypot missing realistic AWS access key")
	}
	if !strings.Contains(script, "${SANDBOX_HOME}/.ssh/id_rsa") {
		t.Error("honeypot missing ssh key")
	}
	if !strings.Contains(script, "BEGIN OPENSSH PRIVATE KEY") {
		t.Error("honeypot missing realistic SSH key format")
	}
	if !strings.Contains(script, "${SANDBOX_HOME}/.kube/config") {
		t.Error("honeypot missing kube config")
	}
	if !strings.Contains(script, "${SANDBOX_HOME}/.env") {
		t.Error("honeypot missing .env file")
	}
	if !strings.Contains(script, "${SANDBOX_HOME}/.git-credentials") {
		t.Error("honeypot missing .git-credentials")
	}
	if !strings.Contains(script, "${SANDBOX_HOME}/.npmrc") {
		t.Error("honeypot missing .npmrc")
	}
}

func TestWorkspaceHoneypotScript(t *testing.T) {
	script := workspaceDotEnvScript()
	if !strings.Contains(script, "/workspace/.env") {
		t.Error("workspace honeypot missing /workspace/.env")
	}
}

func TestStraceTraceSetContainsExpectedSyscalls(t *testing.T) {
	expected := []string{
		"open", "openat", "connect", "execve",
		"chmod", "setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid", "setgroups",
		"symlink", "symlinkat", "memfd_create", "ptrace",
		"socket", "bind", "listen", "sendto", "sendmsg", "sendmmsg", "sendfile", "splice",
		"renameat2", "truncate", "chown", "fchownat", "mount", "umount2", "capset",
	}
	for _, syscall := range expected {
		if !strings.Contains(StraceTraceSet, syscall) {
			t.Errorf("StraceTraceSet missing syscall: %s", syscall)
		}
	}
}

func TestResetMutableStateScript(t *testing.T) {
	script := resetMutableStateScript()
	for _, want := range []string{
		"SANDBOX_HOME",
		"/tmp/",
		"/var/tmp/",
		".npm",
		".cache",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("reset script missing %q", want)
		}
	}
}

func TestImageTagIsFloating(t *testing.T) {
	if !imageTagIsFloating("node:current-slim") {
		t.Fatal("expected node:current-slim to be floating")
	}
	if !imageTagIsFloating("ubuntu:latest") {
		t.Fatal("expected :latest to be floating")
	}
	if imageTagIsFloating("node:20.18.0") {
		t.Fatal("did not expect pinned tag to be floating")
	}
	if imageTagIsFloating("node@sha256:abc") {
		// no colon tag form used here; digest form with :sha256:
		t.Log("skipped @ digest form")
	}
	if imageTagIsFloating("ghcr.io/example/img:sha256:deadbeef") {
		t.Fatal("digest tag should not be treated as floating")
	}
}
