package sandbox

import (
	"context"
	"fmt"
	"io"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
)

// SandboxOptions controls sandbox security policies.
type SandboxOptions struct {
	NetworkEnabled bool
	RunAsRoot      bool
}

type Sandbox struct {
	cli            *client.Client
	image          string
	containerID    string
	runtime        string
	networkEnabled bool
	runAsRoot      bool
}

func NewSandbox(ctx context.Context, image string, opts SandboxOptions) (*Sandbox, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}

	info, err := cli.Info(ctx)
	if err != nil {
		return nil, err
	}

	runtime := ""
	if _, ok := info.Runtimes["runsc"]; ok {
		runtime = "runsc"
	}

	return &Sandbox{
		cli:            cli,
		image:          image,
		runtime:        runtime,
		networkEnabled: opts.NetworkEnabled,
		runAsRoot:      opts.RunAsRoot,
	}, nil
}

func (s *Sandbox) Runtime() string {
	return s.runtime
}

func (s *Sandbox) NetworkEnabled() bool {
	return s.networkEnabled
}

func (s *Sandbox) EnsureImage(ctx context.Context) error {
	reader, err := s.cli.ImagePull(ctx, s.image, image.PullOptions{})
	if err != nil {
		return err
	}
	defer reader.Close()
	_, _ = io.Copy(io.Discard, reader)
	return nil
}

func (s *Sandbox) RunCommand(ctx context.Context, targetCmd, profileName, image string, requiredTools, setupCommands []string) (io.Reader, error) {
	return s.run(ctx, targetCmd, profileName, image, requiredTools, setupCommands, "")
}

func (s *Sandbox) RunProjectCommand(ctx context.Context, targetCmd, projectPath, profileName, image string, requiredTools, setupCommands []string) (io.Reader, error) {
	return s.run(ctx, targetCmd, profileName, image, requiredTools, setupCommands, projectPath)
}

// straceTraceSet is the full set of syscalls traced by GoAudit.
const straceTraceSet = "open,openat,openat2,connect,execve,chmod,fchmod,fchmodat,rename,unlink,unlinkat,setuid,setgid,setreuid,setregid,socket,bind,listen,symlink,symlinkat,memfd_create,ptrace"

func (s *Sandbox) buildScript(targetCmd, profileName, image string, requiredTools, setupCommands []string, projectPath string) string {
	requiredToolsCheck := ""
	for _, t := range requiredTools {
		requiredToolsCheck += fmt.Sprintf("command -v %s >/dev/null 2>&1 || { echo \"GOAUDIT_RUNTIME_ERROR:missing_tool:%s\" >&2; exit 97; }\n", t, t)
	}
	setupScript := ""
	for _, c := range setupCommands {
		setupScript += c + "\n"
	}

	projectStage := ""
	if projectPath != "" {
		projectStage = `
if [ ! -d /project-ro ]; then
  echo "GOAUDIT_RUNTIME_ERROR:project_mount_missing" >&2
  exit 98
fi
if ! command -v rsync >/dev/null 2>&1; then
  apt-get install -y -qq --no-install-recommends rsync > /dev/null 2>&1 || { echo "GOAUDIT_RUNTIME_ERROR:prep_failed" >&2; exit 98; }
fi
mkdir -p /workspace
rsync -a --exclude node_modules --exclude .git /project-ro/ /workspace/
cd /workspace
`
	} else {
		projectStage = `
mkdir -p /workspace
cd /workspace
`
	}

	// Determine honeypot target directory and execution strategy.
	honeypotSection := ""
	execSection := ""
	if s.runAsRoot {
		honeypotSection = buildHoneypots("/root")
		execSection = fmt.Sprintf(
			"strace -s 256 -f -e trace=%s -o /dev/stderr bash /tmp/target.sh",
			straceTraceSet,
		)
	} else {
		honeypotSection = buildNonRootUserSetup()
		// strace runs as root (needs ptrace capability), target runs as sandbox user.
		execSection = fmt.Sprintf(
			"chown -R 1000:1000 /workspace 2>/dev/null || true\nstrace -s 256 -f -e trace=%s -o /dev/stderr su sandbox -s /bin/bash -c 'cd /workspace && bash /tmp/target.sh'",
			straceTraceSet,
		)
	}

	return fmt.Sprintf(`
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq > /dev/null 2>&1 || { echo "GOAUDIT_RUNTIME_ERROR:prep_failed" >&2; exit 98; }
  apt-get install -y -qq --no-install-recommends strace curl ca-certificates dnsutils > /dev/null 2>&1 || { echo "GOAUDIT_RUNTIME_ERROR:prep_failed" >&2; exit 98; }
fi

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
cat << 'EOF_TARGET_CMD' > /tmp/target.sh
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
`, setupScript, requiredToolsCheck, profileName, image, honeypotSection, projectStage, targetCmd, execSection)
}

func (s *Sandbox) run(ctx context.Context, targetCmd, profileName, image string, requiredTools, setupCommands []string, projectPath string) (io.Reader, error) {
	script := s.buildScript(targetCmd, profileName, image, requiredTools, setupCommands, projectPath)

	pidsLimit := int64(256)
	hostConfig := &container.HostConfig{
		Runtime:    s.runtime,
		AutoRemove: false,
		Resources: container.Resources{
			Memory:    512 * 1024 * 1024, // 512 MB
			CPUPeriod: 100000,
			CPUQuota:  50000, // 50% of one core
			PidsLimit: &pidsLimit,
		},
	}
	if !s.networkEnabled {
		hostConfig.NetworkMode = "none"
	}
	if projectPath != "" {
		hostConfig.Mounts = []mount.Mount{
			{
				Type:     mount.TypeBind,
				Source:   projectPath,
				Target:   "/project-ro",
				ReadOnly: true,
			},
		}
	}

	resp, err := s.cli.ContainerCreate(ctx, &container.Config{
		Image:        s.image,
		Cmd:          []string{"bash", "-c", script},
		Tty:          false,
		AttachStderr: true,
		AttachStdout: true,
	}, hostConfig, nil, nil, "")
	if err != nil {
		return nil, err
	}
	s.containerID = resp.ID

	if err := s.cli.ContainerStart(ctx, s.containerID, container.StartOptions{}); err != nil {
		return nil, err
	}

	logs, err := s.cli.ContainerLogs(ctx, s.containerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
	})
	if err != nil {
		return nil, err
	}

	return logs, nil
}

func (s *Sandbox) Cleanup(ctx context.Context) {
	if s.containerID != "" {
		_ = s.cli.ContainerRemove(ctx, s.containerID, container.RemoveOptions{Force: true})
	}
}

// StraceTraceSet returns the syscall trace set for use in tests.
func StraceTraceSet() string {
	return straceTraceSet
}

// buildHoneypots creates realistic decoy credential files in the given home directory.
func buildHoneypots(home string) string {
	return fmt.Sprintf(`
mkdir -p %[1]s/.ssh %[1]s/.aws %[1]s/.kube
cat > %[1]s/.ssh/id_rsa << 'HONEYPOT_SSH'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBhbGljZUBleGFtcGxlLmNvbSBnb2F1ZGl0LWhvbmV5cG90AAAAJGF1ZGl0
HONEYPOT_SSH
chmod 600 %[1]s/.ssh/id_rsa

cat > %[1]s/.aws/credentials << 'HONEYPOT_AWS'
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1
HONEYPOT_AWS

cat > %[1]s/.kube/config << 'HONEYPOT_KUBE'
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://k8s.example.com:6443
    certificate-authority-data: LS0tLS1CRUdJTi...
  name: production
contexts:
- context:
    cluster: production
    user: admin
  name: prod-context
current-context: prod-context
users:
- name: admin
  user:
    token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.goaudit-honeypot
HONEYPOT_KUBE

echo 'DATABASE_URL=postgres://admin:s3cret@db.example.com:5432/prod' > %[1]s/.env
echo 'API_SECRET=sk_live_goaudit_honeypot_4f8a2b1c9d3e' >> %[1]s/.env
`, home)
}

// buildNonRootUserSetup creates a sandbox user and sets up honeypots for it.
func buildNonRootUserSetup() string {
	return `
useradd -m -u 1000 -s /bin/bash sandbox 2>/dev/null || true
` + buildHoneypots("/home/sandbox") + `
chown -R 1000:1000 /home/sandbox
`
}
