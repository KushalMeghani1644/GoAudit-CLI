package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/diagnostic"
	cerrdefs "github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

// SandboxOptions controls sandbox security policies.
type SandboxOptions struct {
	NetworkEnabled bool
}

type Sandbox struct {
	cli              *client.Client
	image            string
	containerID      string
	ephemeralID      string
	ephemeralImageID string
	runtime          string
	networkEnabled   bool
}

func NewSandbox(ctx context.Context, image string, opts SandboxOptions) (*Sandbox, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, diagnostic.New(
			"Cannot initialize Docker.",
			diagnostic.Cause("GoAudit uses Docker to create the sandbox, but the Docker client could not be configured."),
			diagnostic.Hint("Check DOCKER_HOST and Docker environment variables."),
			diagnostic.Hint("Verify Docker works with: docker version"),
			diagnostic.Wrap(err),
		)
	}

	runtime, err := detectRuntime(ctx, cli)
	if err != nil {
		cli.Close()
		return nil, err
	}

	return &Sandbox{
		cli:            cli,
		image:          image,
		runtime:        runtime,
		networkEnabled: opts.NetworkEnabled,
	}, nil
}

func (s *Sandbox) Runtime() string          { return s.runtime }
func (s *Sandbox) SetRuntime(r string)      { s.runtime = r }
func (s *Sandbox) SetImage(image string)    { s.image = image }
func (s *Sandbox) Image() string            { return s.image }
func (s *Sandbox) NetworkEnabled() bool     { return s.networkEnabled }
func (s *Sandbox) ContainerID() string      { return s.containerID }
func (s *Sandbox) SetContainerID(id string) { s.containerID = id }

// imageTagIsFloating reports tags that should be re-pulled rather than reused from a
// potentially stale local cache (mutable distro/runtime rolling tags).
func imageTagIsFloating(imageRef string) bool {
	// A digest makes the reference immutable even if it also includes a mutable tag.
	if strings.Contains(imageRef, "@") {
		return false
	}
	// The tag, when present, is the part after the last colon in the final
	// path segment (registry hosts may themselves contain a :port).
	segment := imageRef
	if idx := strings.LastIndex(segment, "/"); idx >= 0 {
		segment = segment[idx+1:]
	}
	colon := strings.LastIndex(segment, ":")
	if colon < 0 {
		// Untagged references resolve to the mutable "latest" tag.
		return true
	}
	tag := segment[colon+1:]
	if tag == "" {
		// Malformed trailing colon; treat like an untagged reference.
		return true
	}
	switch tag {
	case "latest", "current", "current-slim", "stable", "edge", "nightly":
		return true
	}
	// node:current-slim style where the tag contains "current".
	if strings.Contains(tag, "current") {
		return true
	}
	return false
}

func (s *Sandbox) EnsureImage(ctx context.Context) (string, error) {
	// Always pull floating tags (:latest, :current-slim, …) so local caches cannot
	// silently pin an old mutable image. Non-floating tags are reused if present.
	if !imageTagIsFloating(s.image) {
		if _, err := s.cli.ImageInspect(ctx, s.image); err == nil {
			return s.InspectImageDigest(ctx, s.image)
		} else if !cerrdefs.IsNotFound(err) {
			return "", diagnostic.New(
				fmt.Sprintf("Cannot inspect Docker image %s.", s.image),
				diagnostic.Cause("Docker returned an error while checking whether the image exists locally."),
				diagnostic.Hint("Verify Docker is running and that your user can access the Docker daemon."),
				diagnostic.Wrap(err),
			)
		}
	}

	reader, err := s.cli.ImagePull(ctx, s.image, image.PullOptions{})
	if err != nil {
		return "", diagnostic.New(
			fmt.Sprintf("Cannot pull Docker image %s.", s.image),
			diagnostic.Cause("The sandbox image is not available locally and Docker could not pull it."),
			diagnostic.Hints(imagePullHints(s.image)...),
			diagnostic.Wrap(err),
		)
	}
	defer reader.Close()
	dec := json.NewDecoder(reader)
	for {
		var msg struct {
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := dec.Decode(&msg); err != nil {
			if err == io.EOF {
				break
			}
			return "", diagnostic.New(
				fmt.Sprintf("Docker image pull output for %s could not be parsed.", s.image),
				diagnostic.Cause("Docker returned malformed progress output while pulling the sandbox image."),
				diagnostic.Hint("Retry the scan; if it persists, run docker pull "+s.image+" to see the raw Docker error."),
				diagnostic.Wrap(err),
			)
		}
		if msg.Error != "" {
			pullErr := fmt.Errorf("%s", msg.Error)
			if msg.ErrorDetail.Message != "" {
				pullErr = fmt.Errorf("%s: %s", msg.Error, msg.ErrorDetail.Message)
			}
			return "", diagnostic.New(
				fmt.Sprintf("Docker could not pull image %s.", s.image),
				diagnostic.Cause("The registry rejected or failed the image pull."),
				diagnostic.Hints(imagePullHints(s.image)...),
				diagnostic.Wrap(pullErr),
			)
		}
	}
	return s.InspectImageDigest(ctx, s.image)
}

func imagePullHints(img string) []string {
	hints := []string{
		"Verify Docker is running and that the machine has network access to the image registry.",
		"Run docker pull " + img + " to see the registry error directly.",
	}
	if strings.HasPrefix(img, "ghcr.io/") {
		hints = append(hints, "If the registry requires authentication, run docker login ghcr.io.")
	}
	return hints
}

func (s *Sandbox) InspectImageDigest(ctx context.Context, imageRef string) (string, error) {
	inspect, err := s.cli.ImageInspect(ctx, imageRef)
	if err != nil {
		return "", err
	}
	if len(inspect.RepoDigests) > 0 {
		return inspect.RepoDigests[0], nil
	}
	if inspect.ID != "" {
		return inspect.ID, nil
	}
	return "", fmt.Errorf("image digest unavailable for %s", imageRef)
}

func (s *Sandbox) RunCommand(ctx context.Context, targetCmd, probeScript, profileName, image string, requiredTools, setupCommands []string, targetTimeoutValue, probeTimeoutValue string) (io.Reader, error) {
	return s.run(ctx, targetCmd, probeScript, profileName, image, requiredTools, setupCommands, "", targetTimeoutValue, probeTimeoutValue)
}

func (s *Sandbox) RunProjectCommand(ctx context.Context, targetCmd, probeScript, projectPath, profileName, image string, requiredTools, setupCommands []string, targetTimeoutValue, probeTimeoutValue string) (io.Reader, error) {
	return s.run(ctx, targetCmd, probeScript, profileName, image, requiredTools, setupCommands, projectPath, targetTimeoutValue, probeTimeoutValue)
}

// StraceTraceSet is the full set of syscalls traced by GoAudit.
const StraceTraceSet = "open,openat,openat2,connect,execve,chmod,fchmod,fchmodat,rename,renameat,renameat2,link,linkat,mkdir,mkdirat,unlink,unlinkat,truncate,ftruncate,chown,fchown,lchown,fchownat,mount,umount2,capset,setuid,setgid,setreuid,setregid,setresuid,setresgid,setfsuid,setfsgid,setgroups,unshare,setns,clone,chroot,keyctl,bpf,socket,bind,listen,symlink,symlinkat,memfd_create,ptrace,sendto,sendmsg,sendmmsg,sendfile,splice"

const targetTimeout = "180s"
const defaultProbeTimeout = "30s"

func normalizeTimeout(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func tracedPhaseScript(phase, command, timeoutValue string) string {
	varName := "GOAUDIT_TARGET_RC"
	marker := "GOAUDIT_TARGET_EXIT"
	if phase == "probe" {
		varName = "GOAUDIT_PROBE_RC"
		marker = "GOAUDIT_PROBE_EXIT"
	}
	traceFile := fmt.Sprintf("/tmp/goaudit-%s.strace", phase)
	return fmt.Sprintf(`echo "GOAUDIT_RUNTIME_META:phase=%s" >&2
rm -f %s
set +e
timeout %s strace -s 256 -f -e trace=%s -o %s %s
%s=$?
set -e
echo "%s:${%s}" >&2
if [ "${%s}" -eq 124 ]; then
  echo "GOAUDIT_RUNTIME_META:phase=%s;status=timeout" >&2
fi
if [ -s %s ]; then
  cat %s >&2
fi
`, phase, traceFile, timeoutValue, StraceTraceSet, traceFile, command, varName, marker, varName, varName, phase, traceFile, traceFile)
}

func scriptHeredoc(path, content, prefix string) string {
	delimiter := prefix + "_EOF_" + randomToken()
	for strings.Contains(content, delimiter) {
		delimiter = prefix + "_EOF_" + randomToken()
	}
	return fmt.Sprintf("cat << '%s' > %s\n%s\n%s\nchmod +x %s\n", delimiter, path, content, delimiter, path)
}

func randomToken() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func (s *Sandbox) run(ctx context.Context, targetCmd, probeScript, profileName, image string, requiredTools, setupCommands []string, projectPath, targetTimeoutValue, probeTimeoutValue string) (io.Reader, error) {
	targetTimeoutValue = normalizeTimeout(targetTimeoutValue, targetTimeout)
	probeTimeoutValue = normalizeTimeout(probeTimeoutValue, defaultProbeTimeout)
	toolsCheck := ""
	for _, t := range requiredTools {
		toolsCheck += fmt.Sprintf("command -v %s >/dev/null 2>&1 || { echo \"GOAUDIT_RUNTIME_ERROR:missing_tool:%s\" >&2; exit 97; }\n", t, t)
	}
	setupScript := ""
	for _, c := range setupCommands {
		setupScript += c + "\n"
	}

	projectStage := workspaceHoneypotScript() + "mkdir -p /workspace\ncd /workspace\n"
	if projectPath != "" {
		projectStage = workspaceHoneypotScript() + `
if [ ! -d /project-ro ]; then
  echo "GOAUDIT_RUNTIME_ERROR:project_mount_missing" >&2; exit 98
fi
command -v rsync >/dev/null 2>&1 || { echo "GOAUDIT_RUNTIME_ERROR:missing_tool:rsync" >&2; exit 97; }
mkdir -p /workspace
rsync -a --exclude node_modules --exclude .git /project-ro/ /workspace/ || { echo "GOAUDIT_RUNTIME_ERROR:project_copy_failed" >&2; exit 98; }
cd /workspace
` + workspaceDotEnvScript()
	}

	// Detect an existing uid 1000 (e.g. "node" in node images) or create the
	// unprivileged user that always runs target and probe scripts.
	userSetup := `SANDBOX_USER=$(getent passwd 1000 2>/dev/null | cut -d: -f1)
if [ -z "$SANDBOX_USER" ]; then
  useradd -m -u 1000 -s /bin/bash sandbox 2>/dev/null || true
  SANDBOX_USER=sandbox
fi
SANDBOX_HOME=$(eval echo "~${SANDBOX_USER}")
`
	execLine := `chown -R 1000:1000 /workspace 2>/dev/null || true
` + tracedPhaseScript("target", `runuser -u "$SANDBOX_USER" -- bash -lc 'cd /workspace && bash /tmp/target.sh'`, targetTimeoutValue)

	probeLine := ""
	if strings.TrimSpace(probeScript) != "" {
		catProbe := scriptHeredoc("/tmp/probe.sh", probeScript, "GOAUDIT_PROBE")
		probeLine = catProbe + tracedPhaseScript("probe", `runuser -u "$SANDBOX_USER" -- bash -lc 'cd /workspace && bash /tmp/probe.sh'`, probeTimeoutValue)
	}

	script := fmt.Sprintf(`set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
%s

%s
%s

echo "GOAUDIT_RUNTIME_META:profile=%s;image=%s" >&2
for tool in node npm pnpm bun bash curl strace; do
  if command -v "${tool}" >/dev/null 2>&1; then
    ver="$(${tool} --version 2>/dev/null | head -n1 | tr -d '\r' || true)"
    if [ -n "${ver}" ]; then
      echo "GOAUDIT_RUNTIME_META:tool=${tool};version=${ver}" >&2
    fi
  fi
done

%s
%s
%s

	%s
	%s
	%s
	if [ "${GOAUDIT_TARGET_RC:-0}" -ne 0 ]; then
  exit 99
fi
	`, prepScriptForRuntime(s.runtime), setupScript, toolsCheck, profileName, image,
		userSetup, honeypotScript(), projectStage, scriptHeredoc("/tmp/target.sh", targetCmd, "GOAUDIT_TARGET"), execLine, probeLine)

	pidsLimit := int64(256)
	hostConfig := &container.HostConfig{
		Runtime:    s.runtime,
		AutoRemove: false,
		Resources: container.Resources{
			Memory:    512 * 1024 * 1024,
			CPUPeriod: 100000,
			CPUQuota:  50000,
			PidsLimit: &pidsLimit,
		},
	}
	if s.runtime == "runsc" || projectPath != "" {
		hostConfig.SecurityOpt = []string{"label=disable"}
	}
	if !s.networkEnabled {
		hostConfig.NetworkMode = "none"
	}
	if projectPath != "" {
		hostConfig.Mounts = []mount.Mount{{
			Type: mount.TypeBind, Source: projectPath,
			Target: "/project-ro", ReadOnly: true,
		}}
	}

	resp, err := s.cli.ContainerCreate(ctx, &container.Config{
		Image: s.image, Cmd: []string{"bash", "-c", script},
		Tty: false, AttachStderr: true, AttachStdout: true,
	}, hostConfig, nil, nil, "")
	if err != nil {
		return nil, diagnostic.New(
			"Cannot create sandbox container.",
			diagnostic.Cause("Docker rejected the container configuration for the scan."),
			diagnostic.Hints(containerCreateHints(s.runtime, projectPath)...),
			diagnostic.Wrap(err),
		)
	}
	s.containerID = resp.ID

	if err := s.cli.ContainerStart(ctx, s.containerID, container.StartOptions{}); err != nil {
		return nil, diagnostic.New(
			"Cannot start sandbox container.",
			diagnostic.Cause("Docker created the container but failed to start it."),
			diagnostic.Hint("Check Docker daemon health and available CPU/memory."),
			diagnostic.Wrap(err),
		)
	}

	logs, err := s.cli.ContainerLogs(ctx, s.containerID, container.LogsOptions{
		ShowStdout: true, ShowStderr: true, Follow: true,
	})
	if err != nil {
		return nil, diagnostic.New(
			"Cannot read sandbox logs.",
			diagnostic.Cause("GoAudit started the container but could not attach to its output."),
			diagnostic.Hint("Retry the scan; if it persists, inspect the container logs with docker logs "+s.containerID+"."),
			diagnostic.Wrap(err),
		)
	}
	pr, pw := io.Pipe()
	go func() {
		defer logs.Close()
		_, copyErr := stdcopy.StdCopy(pw, pw, logs)
		_ = pw.CloseWithError(copyErr)
	}()
	return pr, nil
}

func containerCreateHints(runtime, projectPath string) []string {
	hints := []string{"Run docker info to verify the Docker daemon is healthy."}
	if runtime == "runsc" {
		hints = append(hints, "If the error mentions runtime runsc, install/register gVisor or rerun without the runsc Docker runtime.")
	}
	if projectPath != "" {
		hints = append(hints, "If the error mentions a bind mount, verify the project path is shared with Docker: "+projectPath)
	}
	return hints
}

// Cleanup removes or stops the sandbox container.
// If keepCached is true, the container is stopped but not removed (for caching).
func (s *Sandbox) Cleanup(ctx context.Context, keepCached bool) {
	hadEphemeral := s.ephemeralID != ""
	if s.ephemeralID != "" {
		_ = s.cli.ContainerRemove(ctx, s.ephemeralID, container.RemoveOptions{Force: true})
		s.ephemeralID = ""
	}
	if s.ephemeralImageID != "" {
		_, _ = s.cli.ImageRemove(ctx, s.ephemeralImageID, image.RemoveOptions{Force: true, PruneChildren: true})
		s.ephemeralImageID = ""
	}
	if hadEphemeral && !keepCached {
		return
	}
	if s.containerID == "" {
		return
	}
	if keepCached {
		timeout := 5
		_ = s.cli.ContainerStop(ctx, s.containerID, container.StopOptions{Timeout: &timeout})
	} else {
		_ = s.cli.ContainerRemove(ctx, s.containerID, container.RemoveOptions{Force: true})
		s.containerID = ""
	}
}

// PrepareWarm creates a container, runs the full prep script (apt, honeypots, user setup),
// and stops it. The container is left in a stopped state ready for ExecScan.
func (s *Sandbox) PrepareWarm(ctx context.Context, profileName, img string, requiredTools, setupCommands []string) error {
	toolsCheck := ""
	for _, t := range requiredTools {
		toolsCheck += fmt.Sprintf("command -v %s >/dev/null 2>&1 || { echo \"GOAUDIT_RUNTIME_ERROR:missing_tool:%s\" >&2; exit 97; }\n", t, t)
	}
	setupScript := ""
	for _, c := range setupCommands {
		setupScript += c + "\n"
	}

	userSetup := `SANDBOX_USER=$(getent passwd 1000 2>/dev/null | cut -d: -f1)
if [ -z "$SANDBOX_USER" ]; then
  useradd -m -u 1000 -s /bin/bash sandbox 2>/dev/null || true
  SANDBOX_USER=sandbox
fi
SANDBOX_HOME=$(eval echo "~${SANDBOX_USER}")
`

	prepScript := fmt.Sprintf(`set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
%s

%s
%s

%s
%s

mkdir -p /workspace
echo "GOAUDIT_WARM_READY" >&2
	`, prepScriptForRuntime(s.runtime), setupScript, toolsCheck, userSetup, honeypotScript())

	pidsLimit := int64(256)
	hostConfig := &container.HostConfig{
		Runtime:    s.runtime,
		AutoRemove: false,
		Resources: container.Resources{
			Memory:    512 * 1024 * 1024,
			CPUPeriod: 100000,
			CPUQuota:  50000,
			PidsLimit: &pidsLimit,
		},
	}
	if s.runtime == "runsc" {
		hostConfig.SecurityOpt = []string{"label=disable"}
	}
	if !s.networkEnabled {
		hostConfig.NetworkMode = "none"
	}

	resp, err := s.cli.ContainerCreate(ctx, &container.Config{
		Image: s.image, Cmd: []string{"bash", "-lc", "while true; do sleep 3600; done"},
		Tty: false, AttachStderr: true, AttachStdout: true,
	}, hostConfig, nil, nil, "")
	if err != nil {
		return fmt.Errorf("container create: %w", err)
	}
	s.containerID = resp.ID

	if err := s.cli.ContainerStart(ctx, s.containerID, container.StartOptions{}); err != nil {
		return fmt.Errorf("container start: %w", err)
	}

	prepOutput, exitCode, err := s.execScript(ctx, prepScript)
	if err != nil {
		return fmt.Errorf("warm prep exec: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("warm prep failed (exit %d): %s", exitCode, prepOutput)
	}

	timeout := 5
	_ = s.cli.ContainerStop(ctx, s.containerID, container.StopOptions{Timeout: &timeout})
	return nil
}

// sandboxHomeGuardScript defines a shell helper that reports whether a path is
// a dedicated home directory that may be recursively wiped between warm cached
// scans. A misconfigured cacheable image (for example uid 1000 with home / or
// /root) must never cause the reset to delete top-level system directories or
// root's home.
func sandboxHomeGuardScript() string {
	return `goaudit_home_is_dedicated() {
  case "$(cd "${1:-/goaudit-nonexistent}" 2>/dev/null && pwd)" in
  ""|/|//|/bin|/boot|/dev|/etc|/home|/lib|/lib32|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var|/workspace)
    return 1
    ;;
  *)
    return 0
    ;;
  esac
}
`
}

// resetMutableStateScript clears user-writable state left by a prior scan so
// warm-container reuse does not leak configs, caches, or PATH-controlled files.
func resetMutableStateScript() string {
	return fmt.Sprintf(`
# --- goaudit: reset mutable state between cached scans ---
rm -rf /tmp/* /tmp/.[!.]* /tmp/..?* /var/tmp/* /var/tmp/.[!.]* /var/tmp/..?* 2>/dev/null || true
%s
if [ -n "${SANDBOX_HOME:-}" ] && [ -d "${SANDBOX_HOME}" ]; then
  if goaudit_home_is_dedicated "${SANDBOX_HOME}"; then
    # Wipe home contents (including package-manager caches and user configs).
    find "${SANDBOX_HOME}" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true
  else
    echo "GOAUDIT_RUNTIME_META:home_reset=skipped;reason=unsafe_sandbox_home" >&2
  fi
fi
# Common non-home caches that installers may create.
rm -rf /root/.npm /root/.cache /root/.config /root/.local /root/.bun /root/.pnpm-store 2>/dev/null || true
rm -rf /home/*/.npm /home/*/.cache /home/*/.config /home/*/.local /home/*/.bun 2>/dev/null || true
rm -rf /usr/local/share/.cache 2>/dev/null || true
`, sandboxHomeGuardScript())
}

// ExecScan runs a scan command on an already-prepared (warm) container.
// The container should have been created by PrepareWarm and be in a stopped state.
func (s *Sandbox) ExecScan(ctx context.Context, targetCmd, probeScript, profileName, img string, projectPath string, targetTimeoutValue, probeTimeoutValue string) (io.Reader, error) {
	if projectPath != "" {
		return nil, fmt.Errorf("cached project scans are not supported")
	}
	targetTimeoutValue = normalizeTimeout(targetTimeoutValue, targetTimeout)
	probeTimeoutValue = normalizeTimeout(probeTimeoutValue, defaultProbeTimeout)

	// Ensure the container is running.
	inspect, err := s.cli.ContainerInspect(ctx, s.containerID)
	if err != nil {
		return nil, fmt.Errorf("container inspect: %w", err)
	}
	if !inspect.State.Running {
		if err := s.cli.ContainerStart(ctx, s.containerID, container.StartOptions{}); err != nil {
			return nil, fmt.Errorf("container start: %w", err)
		}
	}

	// Resolve sandbox user home, wipe residual state from prior scans, then re-honeypot.
	userSetup := `SANDBOX_USER=$(getent passwd 1000 2>/dev/null | cut -d: -f1 || echo sandbox)
SANDBOX_HOME=$(eval echo "~${SANDBOX_USER}")` + "\n"

	execLine := `chown -R 1000:1000 /workspace 2>/dev/null || true
` + tracedPhaseScript("target", `runuser -u "$SANDBOX_USER" -- bash -lc 'cd /workspace && bash /tmp/target.sh'`, targetTimeoutValue)

	probeLine := ""
	if strings.TrimSpace(probeScript) != "" {
		catProbe := scriptHeredoc("/tmp/probe.sh", probeScript, "GOAUDIT_PROBE")
		probeLine = catProbe + tracedPhaseScript("probe", `runuser -u "$SANDBOX_USER" -- bash -lc 'cd /workspace && bash /tmp/probe.sh'`, probeTimeoutValue)
	}

	scanScript := fmt.Sprintf(`set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "GOAUDIT_RUNTIME_META:profile=%s;image=%s" >&2
for tool in node npm pnpm bun bash curl strace; do
  if command -v "${tool}" >/dev/null 2>&1; then
    ver="$(${tool} --version 2>/dev/null | head -n1 | tr -d '\r' || true)"
    if [ -n "${ver}" ]; then
      echo "GOAUDIT_RUNTIME_META:tool=${tool};version=${ver}" >&2
    fi
  fi
done

%s
%s
%s

rm -rf /workspace/* /workspace/.[!.]* /workspace/..?* 2>/dev/null || true
mkdir -p /workspace
%s
cd /workspace
%s

%s
%s
if [ "${GOAUDIT_TARGET_RC:-0}" -ne 0 ]; then
  exit 99
fi
`, profileName, img, userSetup, resetMutableStateScript(), honeypotScript(), workspaceHoneypotScript(), scriptHeredoc("/tmp/target.sh", targetCmd, "GOAUDIT_TARGET"), execLine, probeLine)

	execCfg := container.ExecOptions{
		AttachStderr: true,
		AttachStdout: true,
		Cmd:          []string{"bash", "-lc", scanScript},
	}
	execResp, err := s.cli.ContainerExecCreate(ctx, s.containerID, execCfg)
	if err != nil {
		return nil, fmt.Errorf("exec create: %w", err)
	}

	attach, err := s.cli.ContainerExecAttach(ctx, execResp.ID, container.ExecStartOptions{})
	if err != nil {
		return nil, fmt.Errorf("exec attach: %w", err)
	}

	pr, pw := io.Pipe()
	go func() {
		defer attach.Close()
		defer func() {
			timeout := 5
			_ = s.cli.ContainerStop(context.Background(), s.containerID, container.StopOptions{Timeout: &timeout})
		}()
		_, copyErr := stdcopy.StdCopy(pw, pw, attach.Reader)
		_ = pw.CloseWithError(copyErr)
	}()
	return pr, nil
}

func (s *Sandbox) execScript(ctx context.Context, script string) (string, int, error) {
	execCfg := container.ExecOptions{
		AttachStderr: true,
		AttachStdout: true,
		Cmd:          []string{"bash", "-lc", script},
	}
	execResp, err := s.cli.ContainerExecCreate(ctx, s.containerID, execCfg)
	if err != nil {
		return "", 0, err
	}
	attach, err := s.cli.ContainerExecAttach(ctx, execResp.ID, container.ExecStartOptions{})
	if err != nil {
		return "", 0, err
	}
	defer attach.Close()

	var out bytes.Buffer
	_, _ = stdcopy.StdCopy(&out, &out, attach.Reader)

	var inspect container.ExecInspect
	for {
		inspect, err = s.cli.ContainerExecInspect(ctx, execResp.ID)
		if err != nil {
			return out.String(), 0, err
		}
		if !inspect.Running {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return out.String(), inspect.ExitCode, nil
}

// honeypotScript creates realistic decoy credential files using $SANDBOX_HOME shell variable.
func honeypotScript() string {
	return `mkdir -p "${SANDBOX_HOME}/.ssh" "${SANDBOX_HOME}/.aws" "${SANDBOX_HOME}/.kube" 2>/dev/null || true
cat > "${SANDBOX_HOME}/.ssh/id_rsa" << 'HONEYPOT_SSH'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBqkSeSrbynBuV6IWHjU/bQh8hku4bwObCTmMBD7dQmbQAAAKBAx/jaQMf4
2gAAAAtzc2gtZWQyNTUxOQAAACBqkSeSrbynBuV6IWHjU/bQh8hku4bwObCTmMBD7dQmbQ
AAAEDR9kJynnF3Y5r1Bcpmij8xaHduUL0ieGLJQflZYs68/2qRJ5KtvKcG5XohYeNT9tCH
yGS7hvA5sJOYwEPt1CZtAAAAFmRlcGxveUBidWlsZC13b3JrZXItMDcBAgMEBQYH
-----END OPENSSH PRIVATE KEY-----
HONEYPOT_SSH
chmod 600 "${SANDBOX_HOME}/.ssh/id_rsa"
cat > "${SANDBOX_HOME}/.aws/credentials" << 'HONEYPOT_AWS'
[default]
aws_access_key_id = AKIAY7M4N2Q8V6C3Z5PX
aws_secret_access_key = F8vK3qN7xR2mP9sT4wY6aC1dE5gH8jL0uB3iO7zQ
region = us-east-1
HONEYPOT_AWS
cat > "${SANDBOX_HOME}/.kube/config" << 'HONEYPOT_KUBE'
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://k8s.prod.corp:6443
  name: production
users:
- name: admin
  user:
    token: eyJhbGciOiJSUzI1NiIsImtpZCI6Ims4cy1wcm9kLTA3In0.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OnByb2Q6ZGVwbG95ZXIifQ.0DakOk6_ztCjTAZz03iZl15-ovcD_oehLTprn0QyRy_aTvOkU_2VotC0esCS-muZt3XcBltRWkYW5QZofYdsTPxd4N12tdNb350y-vmiEaEim4TeuRcupl11CQgFkJhrIywLh861SIGBqwbNUIhWhTIja3bMLRq2p7LyHcxpVZZeIzA0BTxUSWyfjgLZ79-BCAOo6BdPo73hMfPiwuZ1tKbuii6XpX911krDdCEO5B_EGKj1GAaeKvOMsk7kOoAQ62VButdFUZLDCLFMVHbq72jolDvFSaQg2n-bvyD9g_t-ZA_TXh6h9OFrlFl4dIHlvg4kffrTXTX-pv1ENqb_ZA
HONEYPOT_KUBE
echo 'DATABASE_URL=postgres://admin:s3cret@db.prod.corp:5432/prod' > "${SANDBOX_HOME}/.env"
echo 'API_SECRET=api_live_Q7m2X9v4K6p8N3c5R1t0Y2w4' >> "${SANDBOX_HOME}/.env"
echo 'https://token:ghp_R7mN4kQ2vX9cL6sD3fH8jP5wT1yB0aE7uI2o@github.com' > "${SANDBOX_HOME}/.git-credentials"
chmod 600 "${SANDBOX_HOME}/.git-credentials" 2>/dev/null || true
echo '//registry.npmjs.org/:_authToken=npm_8Kz3pQ7vN2xM9cR4tY6wF1hJ5sL0dB8gQ4xV' > "${SANDBOX_HOME}/.npmrc"
if [ -n "$SANDBOX_USER" ] && [ "$SANDBOX_USER" != "root" ]; then
  chown -R 1000:1000 "${SANDBOX_HOME}" 2>/dev/null || true
fi
`
}

func workspaceHoneypotScript() string {
	return workspaceDotEnvScript()
}

func workspaceDotEnvScript() string {
	return `mkdir -p /workspace 2>/dev/null || true
echo 'DATABASE_URL=postgres://admin:s3cret@db.prod.corp:5432/prod' > /workspace/.env
echo 'API_SECRET=api_live_M8p4V2x7R9k1C6n3T5w0H2q8' >> /workspace/.env
`
}
