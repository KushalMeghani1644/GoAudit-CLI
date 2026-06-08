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
		"chmod", "setuid", "setgid",
		"symlink", "symlinkat", "memfd_create", "ptrace",
		"socket", "bind", "listen", "sendto", "sendmsg", "write",
	}
	for _, syscall := range expected {
		if !strings.Contains(StraceTraceSet, syscall) {
			t.Errorf("StraceTraceSet missing syscall: %s", syscall)
		}
	}
}
