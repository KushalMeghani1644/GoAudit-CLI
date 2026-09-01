package sandbox

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
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
	tests := []struct {
		name     string
		imageRef string
		want     bool
	}{
		{name: "current tag", imageRef: "node:current-slim", want: true},
		{name: "latest tag", imageRef: "ubuntu:latest", want: true},
		{name: "registry qualified latest tag", imageRef: "ghcr.io/kushalmeghani1644/goaudit-node-sandbox:latest", want: true},
		{name: "registry port and floating tag", imageRef: "localhost:5000/example/img:edge", want: true},
		{name: "pinned tag", imageRef: "node:20.18.0", want: false},
		{name: "registry port and pinned tag", imageRef: "localhost:5000/example/img:1.2.3", want: false},
		// Untagged references resolve to the mutable "latest" tag, so they must
		// be re-pulled instead of reused from a stale local cache.
		{name: "untagged registry port", imageRef: "localhost:5000/example/img", want: true},
		{name: "untagged registry reference", imageRef: "ghcr.io/example/img", want: true},
		{name: "unqualified untagged reference", imageRef: "node", want: true},
		{name: "digest", imageRef: "node@sha256:abc", want: false},
		{name: "tag with digest", imageRef: "node:latest@sha256:abc", want: false},
		{name: "legacy digest-shaped tag", imageRef: "ghcr.io/example/img:sha256:deadbeef", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := imageTagIsFloating(tt.imageRef); got != tt.want {
				t.Fatalf("imageTagIsFloating(%q) = %v, want %v", tt.imageRef, got, tt.want)
			}
		})
	}
}

// TestResetMutableStateScriptRejectsSystemHomePaths is a regression test for
// warm-cache reuse on cacheable images where the exec shell runs as root and
// uid 1000 has home /: the reset must refuse to recursively delete / and any
// other non-dedicated system path before the target runs.
func TestResetMutableStateScriptRejectsSystemHomePaths(t *testing.T) {
	script := resetMutableStateScript()
	if !strings.Contains(script, "goaudit_home_is_dedicated") {
		t.Fatal("reset script does not guard the SANDBOX_HOME wipe before recursive deletion")
	}
	if !strings.Contains(script, `find "${SANDBOX_HOME}" -mindepth 1 -maxdepth 1`) {
		t.Fatal("reset script lost the home wipe")
	}

	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}

	// Run the actual guard helper in bash. Unsafe paths must be rejected and
	// a dedicated, existing home directory must still be accepted.
	unsafe := []string{
		"/", "//", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32",
		"/lib64", "/media", "/mnt", "/opt", "/proc", "/root", "/run", "/sbin",
		"/srv", "/sys", "/tmp", "/usr", "/var", "/workspace",
	}
	dedicated := t.TempDir()
	check := sandboxHomeGuardScript() + `
failed=0
for p in "$@"; do
  if goaudit_home_is_dedicated "$p"; then
    echo "UNSAFE_ACCEPTED:$p"
    failed=1
  fi
done
if ! goaudit_home_is_dedicated "$DEDICATED"; then
  echo "DEDICATED_REJECTED:$DEDICATED"
  failed=1
fi
mkdir -p "$DEDICATED/nested"
if ! goaudit_home_is_dedicated "$DEDICATED/nested"; then
  echo "DEDICATED_REJECTED:$DEDICATED/nested"
  failed=1
fi
exit $failed
`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	args := append([]string{"-c", check, "goaudit-home-guard-test"}, unsafe...)
	cmd := exec.CommandContext(ctx, "bash", args...)
	cmd.Env = append(cmd.Environ(), "DEDICATED="+dedicated)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			t.Fatalf("sandbox home guard test timed out:\n%s", out)
		}
		t.Fatalf("sandbox home guard misclassified paths:\n%s", out)
	}
}
