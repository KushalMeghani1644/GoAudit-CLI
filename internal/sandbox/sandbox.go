package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

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
	RunAsRoot      bool
}

type Sandbox struct {
	cli              *client.Client
	image            string
	containerID      string
	ephemeralID      string
	ephemeralImageID string
	runtime          string
	networkEnabled   bool
	runAsRoot        bool
}

func NewSandbox(ctx context.Context, image string, opts SandboxOptions) (*Sandbox, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}

	runtime := detectRuntime(ctx, cli)

	return &Sandbox{
		cli:            cli,
		image:          image,
		runtime:        runtime,
		networkEnabled: opts.NetworkEnabled,
		runAsRoot:      opts.RunAsRoot,
	}, nil
}

func (s *Sandbox) Runtime() string          { return s.runtime }
func (s *Sandbox) SetRuntime(r string)      { s.runtime = r }
func (s *Sandbox) SetImage(image string)    { s.image = image }
func (s *Sandbox) Image() string            { return s.image }
func (s *Sandbox) NetworkEnabled() bool     { return s.networkEnabled }
func (s *Sandbox) ContainerID() string      { return s.containerID }
func (s *Sandbox) SetContainerID(id string) { s.containerID = id }

func (s *Sandbox) EnsureImage(ctx context.Context) (string, error) {
	// Always pull :latest tags to pick up newly published sandbox images.
	if !strings.HasSuffix(s.image, ":latest") {
		if _, err := s.cli.ImageInspect(ctx, s.image); err == nil {
			return s.InspectImageDigest(ctx, s.image)
		} else if !cerrdefs.IsNotFound(err) {
			return "", err
		}
	}

	reader, err := s.cli.ImagePull(ctx, s.image, image.PullOptions{})
	if err != nil {
		return "", err
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
			return "", err
		}
		if msg.Error != "" {
			if msg.ErrorDetail.Message != "" {
				return "", fmt.Errorf("%s: %s", msg.Error, msg.ErrorDetail.Message)
			}
			return "", fmt.Errorf("%s", msg.Error)
		}
	}
	return s.InspectImageDigest(ctx, s.image)
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

func (s *Sandbox) RunCommand(ctx context.Context, targetCmd, profileName, image string, requiredTools, setupCommands []string) (io.Reader, error) {
	return s.run(ctx, targetCmd, profileName, image, requiredTools, setupCommands, "")
}

func (s *Sandbox) RunProjectCommand(ctx context.Context, targetCmd, projectPath, profileName, image string, requiredTools, setupCommands []string) (io.Reader, error) {
	return s.run(ctx, targetCmd, profileName, image, requiredTools, setupCommands, projectPath)
}

// StraceTraceSet is the full set of syscalls traced by GoAudit.
const StraceTraceSet = "open,openat,openat2,connect,execve,chmod,fchmod,fchmodat,rename,unlink,unlinkat,setuid,setgid,setreuid,setregid,socket,bind,listen,symlink,symlinkat,memfd_create,ptrace"

const targetTimeout = "90s"

func (s *Sandbox) run(ctx context.Context, targetCmd, profileName, image string, requiredTools, setupCommands []string, projectPath string) (io.Reader, error) {
	toolsCheck := ""
	for _, t := range requiredTools {
		toolsCheck += fmt.Sprintf("command -v %s >/dev/null 2>&1 || { echo \"GOAUDIT_RUNTIME_ERROR:missing_tool:%s\" >&2; exit 97; }\n", t, t)
	}
	setupScript := ""
	for _, c := range setupCommands {
		setupScript += c + "\n"
	}

	projectStage := "mkdir -p /workspace\ncd /workspace\n"
	if projectPath != "" {
		projectStage = `
if [ ! -d /project-ro ]; then
  echo "GOAUDIT_RUNTIME_ERROR:project_mount_missing" >&2; exit 98
fi
command -v rsync >/dev/null 2>&1 || apt-get install -y -qq --no-install-recommends rsync > /dev/null 2>&1 || { echo "GOAUDIT_RUNTIME_ERROR:prep_failed" >&2; exit 98; }
mkdir -p /workspace
rsync -a --exclude node_modules --exclude .git /project-ro/ /workspace/ || { echo "GOAUDIT_RUNTIME_ERROR:project_copy_failed" >&2; exit 98; }
cd /workspace
`
	}

	// User setup: detect existing uid 1000 (e.g. "node" in node images) or create sandbox user.
	userSetup := ""
	execLine := ""
	if s.runAsRoot {
		userSetup = `SANDBOX_HOME="/root"
`
		execLine = fmt.Sprintf(
			`timeout %s strace -s 256 -f -e trace=%s -o /dev/stderr bash /tmp/target.sh`, targetTimeout, StraceTraceSet)
	} else {
		userSetup = `SANDBOX_USER=$(getent passwd 1000 2>/dev/null | cut -d: -f1)
if [ -z "$SANDBOX_USER" ]; then
  useradd -m -u 1000 -s /bin/bash sandbox 2>/dev/null || true
  SANDBOX_USER=sandbox
fi
SANDBOX_HOME=$(eval echo "~${SANDBOX_USER}")
`
		execLine = fmt.Sprintf(
			`chown -R 1000:1000 /workspace 2>/dev/null || true
timeout %s strace -s 256 -f -e trace=%s -o /dev/stderr su "$SANDBOX_USER" -s /bin/bash -c 'cd /workspace && bash /tmp/target.sh'`, targetTimeout, StraceTraceSet)
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
cat << 'EOF_TARGET_CMD' > /tmp/target.sh
echo 'GOAUDIT_RUNTIME_META:phase=target' >&2
%s
EOF_TARGET_CMD
chmod +x /tmp/target.sh

set +e
%s
target_rc=$?
set -e
echo "GOAUDIT_TARGET_EXIT:${target_rc}" >&2
if [ "${target_rc}" -ne 0 ]; then
  exit 99
fi
	`, prepScriptForRuntime(s.runtime), setupScript, toolsCheck, profileName, image,
		userSetup, honeypotScript(), projectStage, targetCmd, execLine)

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
		return nil, err
	}
	s.containerID = resp.ID

	if err := s.cli.ContainerStart(ctx, s.containerID, container.StartOptions{}); err != nil {
		return nil, err
	}

	logs, err := s.cli.ContainerLogs(ctx, s.containerID, container.LogsOptions{
		ShowStdout: true, ShowStderr: true, Follow: true,
	})
	if err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	go func() {
		defer logs.Close()
		_, copyErr := stdcopy.StdCopy(pw, pw, logs)
		_ = pw.CloseWithError(copyErr)
	}()
	return pr, nil
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

	userSetup := ""
	if s.runAsRoot {
		userSetup = `SANDBOX_HOME="/root"
`
	} else {
		userSetup = `SANDBOX_USER=$(getent passwd 1000 2>/dev/null | cut -d: -f1)
if [ -z "$SANDBOX_USER" ]; then
  useradd -m -u 1000 -s /bin/bash sandbox 2>/dev/null || true
  SANDBOX_USER=sandbox
fi
SANDBOX_HOME=$(eval echo "~${SANDBOX_USER}")
`
	}

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

// ExecScan runs a scan command on an already-prepared (warm) container.
// The container should have been created by PrepareWarm and be in a stopped state.
func (s *Sandbox) ExecScan(ctx context.Context, targetCmd, profileName, img string, projectPath string) (io.Reader, error) {
	if projectPath != "" {
		return nil, fmt.Errorf("cached project scans are not supported")
	}

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

	execLine := ""
	if s.runAsRoot {
		execLine = fmt.Sprintf(
			`timeout %s strace -s 256 -f -e trace=%s -o /dev/stderr bash /tmp/target.sh`, targetTimeout, StraceTraceSet)
	} else {
		execLine = fmt.Sprintf(
			`SANDBOX_USER=$(getent passwd 1000 2>/dev/null | cut -d: -f1 || echo sandbox)
chown -R 1000:1000 /workspace 2>/dev/null || true
timeout %s strace -s 256 -f -e trace=%s -o /dev/stderr su "$SANDBOX_USER" -s /bin/bash -c 'cd /workspace && bash /tmp/target.sh'`, targetTimeout, StraceTraceSet)
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

rm -rf /workspace/* /workspace/.[!.]* /workspace/..?* 2>/dev/null || true
cd /workspace
cat << 'EOF_TARGET_CMD' > /tmp/target.sh
echo 'GOAUDIT_RUNTIME_META:phase=target' >&2
%s
EOF_TARGET_CMD
chmod +x /tmp/target.sh

set +e
%s
target_rc=$?
set -e
echo "GOAUDIT_TARGET_EXIT:${target_rc}" >&2
if [ "${target_rc}" -ne 0 ]; then
  exit 99
fi
`, profileName, img, targetCmd, execLine)

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
	return `mkdir -p "${SANDBOX_HOME}/.ssh" "${SANDBOX_HOME}/.aws" "${SANDBOX_HOME}/.kube" || { echo "GOAUDIT_RUNTIME_ERROR:prep_failed" >&2; exit 98; }
cat > "${SANDBOX_HOME}/.ssh/id_rsa" << 'HONEYPOT_SSH'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBhbGljZUBleGFtcGxlLmNvbSBnb2F1ZGl0LWhvbmV5cG90AAAAJGF1ZGl0
HONEYPOT_SSH
chmod 600 "${SANDBOX_HOME}/.ssh/id_rsa"
cat > "${SANDBOX_HOME}/.aws/credentials" << 'HONEYPOT_AWS'
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1
HONEYPOT_AWS
cat > "${SANDBOX_HOME}/.kube/config" << 'HONEYPOT_KUBE'
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://k8s.example.com:6443
  name: production
users:
- name: admin
  user:
    token: eyJhbGciOiJSUzI1NiJ9.goaudit-honeypot
HONEYPOT_KUBE
echo 'DATABASE_URL=postgres://admin:s3cret@db.example.com:5432/prod' > "${SANDBOX_HOME}/.env"
echo 'API_SECRET=sk_live_goaudit_honeypot_4f8a2b1c9d3e' >> "${SANDBOX_HOME}/.env"
if [ -n "$SANDBOX_USER" ] && [ "$SANDBOX_USER" != "root" ]; then
  chown -R 1000:1000 "${SANDBOX_HOME}" 2>/dev/null || true
fi
`
}
