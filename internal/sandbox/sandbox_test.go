package sandbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestHoneypotScript(t *testing.T) {
	script := honeypotScript()

	if !strings.Contains(script, "${SANDBOX_HOME}/.aws/credentials") {
		t.Error("honeypot missing aws credentials")
	}
	if strings.Contains(script, "AKIAIOSFODNN7EXAMPLE") || strings.Contains(script, "EXAMPLEKEY") {
		t.Error("honeypot must not use AWS documentation credentials")
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

func TestHoneypotCredentialsAreParseableAndUnmarked(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	home := t.TempDir()
	cmd := exec.CommandContext(ctx, "bash", "-c", honeypotScript())
	cmd.Env = append(os.Environ(), "SANDBOX_HOME="+home, "SANDBOX_USER=root")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create honeypot files: %v\n%s", err, output)
	}

	keyPath := filepath.Join(home, ".ssh", "id_rsa")
	t.Run("SSH key parses", func(t *testing.T) {
		if _, err := exec.LookPath("ssh-keygen"); err != nil {
			t.Skip("ssh-keygen is required to validate the OpenSSH honeypot key")
		}
		if output, err := exec.CommandContext(ctx, "ssh-keygen", "-y", "-f", keyPath).CombinedOutput(); err != nil {
			t.Fatalf("honeypot SSH key does not parse: %v\n%s", err, output)
		}
	})

	awsBytes, err := os.ReadFile(filepath.Join(home, ".aws", "credentials"))
	if err != nil {
		t.Fatalf("read AWS credentials: %v", err)
	}
	aws := string(awsBytes)
	if !regexp.MustCompile(`(?m)^aws_access_key_id = AKIA[A-Z0-9]{16}$`).MatchString(aws) {
		t.Fatalf("AWS access key does not have a valid-looking format:\n%s", aws)
	}
	if !regexp.MustCompile(`(?m)^aws_secret_access_key = [A-Za-z0-9/+=]{40}$`).MatchString(aws) {
		t.Fatalf("AWS secret key does not have a valid-looking format:\n%s", aws)
	}

	kubeBytes, err := os.ReadFile(filepath.Join(home, ".kube", "config"))
	if err != nil {
		t.Fatalf("read Kubernetes config: %v", err)
	}
	tokenMatch := regexp.MustCompile(`(?m)^\s*token: (\S+)$`).FindSubmatch(kubeBytes)
	if tokenMatch == nil {
		t.Fatal("Kubernetes config does not contain a token")
	}
	tokenParts := strings.Split(string(tokenMatch[1]), ".")
	if len(tokenParts) != 3 {
		t.Fatalf("Kubernetes token has %d segments, want 3", len(tokenParts))
	}
	decodeJSONSegment := func(name, segment string, target any) {
		decoded, err := base64.RawURLEncoding.DecodeString(segment)
		if err != nil {
			t.Fatalf("Kubernetes token %s is not valid base64url: %v", name, err)
		}
		if err := json.Unmarshal(decoded, target); err != nil {
			t.Fatalf("Kubernetes token %s is not valid JSON: %v", name, err)
		}
	}
	var header struct {
		Algorithm string `json:"alg"`
	}
	decodeJSONSegment("header", tokenParts[0], &header)
	if header.Algorithm != "RS256" {
		t.Fatalf("Kubernetes token algorithm is %q, want RS256", header.Algorithm)
	}
	var payload map[string]any
	decodeJSONSegment("payload", tokenParts[1], &payload)
	if payload == nil {
		t.Fatal("Kubernetes token payload is not a JSON object")
	}

	signature, err := base64.RawURLEncoding.DecodeString(tokenParts[2])
	if err != nil {
		t.Fatalf("Kubernetes token signature is not valid base64url: %v", err)
	}
	if len(signature) != 256 {
		t.Fatalf("Kubernetes token signature is %d bytes, want 256 for RS256", len(signature))
	}
	printableSignature := true
	for _, b := range signature {
		if b < 0x20 || b > 0x7e {
			printableSignature = false
			break
		}
	}
	if printableSignature {
		t.Fatalf("Kubernetes token signature contains readable placeholder content: %q", signature)
	}

	credentialPaths := []string{
		keyPath,
		filepath.Join(home, ".aws", "credentials"),
		filepath.Join(home, ".kube", "config"),
		filepath.Join(home, ".env"),
		filepath.Join(home, ".git-credentials"),
		filepath.Join(home, ".npmrc"),
	}
	for _, path := range credentialPaths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		lower := strings.ToLower(string(content))
		for _, marker := range []string{"goaudit", "honeypot", "examplekey", "akiaiosfodnn7example"} {
			if strings.Contains(lower, marker) {
				t.Errorf("%s contains self-identifying marker %q", path, marker)
			}
		}
	}
}

func TestWorkspaceHoneypotScript(t *testing.T) {
	script := workspaceDotEnvScript()
	if !strings.Contains(script, "/workspace/.env") {
		t.Error("workspace honeypot missing /workspace/.env")
	}
	if strings.Contains(strings.ToLower(script), "goaudit") || strings.Contains(strings.ToLower(script), "honeypot") {
		t.Error("workspace honeypot values must not identify the scanner")
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
