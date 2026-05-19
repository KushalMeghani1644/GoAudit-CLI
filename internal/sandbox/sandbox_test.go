package sandbox

import (
	"context"
	"strings"
	"testing"
)

func TestNewSandbox_Options(t *testing.T) {
	opts := SandboxOptions{
		NetworkEnabled: true,
		RunAsRoot:      true,
	}

	sb, err := NewSandbox(context.Background(), "ubuntu:latest", opts)
	if err != nil {
		t.Fatalf("unexpected error creating sandbox: %v", err)
	}

	if !sb.NetworkEnabled() {
		t.Errorf("expected NetworkEnabled to be true")
	}
}

func TestSandbox_buildScript(t *testing.T) {
	sb := &Sandbox{
		image:          "ubuntu:latest",
		networkEnabled: false,
		runAsRoot:      false,
	}

	script := sb.buildScript("echo hello", "test-profile", "ubuntu:latest", nil, nil, "")

	if !strings.Contains(script, "apt-get install -y") {
		t.Errorf("script missing apt-get installation")
	}

	// Verify honeypot creation
	if !strings.Contains(script, "/home/sandbox/.aws/credentials") {
		t.Errorf("script missing aws credentials honeypot")
	}

	// Verify strace command
	expectedStrace := "strace -s 256 -f -e trace=" + straceTraceSet
	if !strings.Contains(script, expectedStrace) {
		t.Errorf("script missing complete strace command. Expected %s", expectedStrace)
	}

	// Verify non-root execution since runAsRoot is false
	if !strings.Contains(script, "su sandbox") {
		t.Errorf("script missing 'su sandbox' for non-root execution")
	}

	// Verify root execution when requested
	sbRoot := &Sandbox{
		runAsRoot: true,
	}
	scriptRoot := sbRoot.buildScript("echo hello", "test-profile", "ubuntu:latest", nil, nil, "")
	if strings.Contains(scriptRoot, "su sandbox -c") {
		t.Errorf("script should not use 'su sandbox' when runAsRoot is true")
	}
	if !strings.Contains(scriptRoot, "bash /tmp/target.sh") {
		t.Errorf("script missing the command execution")
	}
}
