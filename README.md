<h1 align="center">
  <img src="assets/favicon.png" width="150" />
</h1>

GoAudit is a sandbox security scanner for JavaScript package installs.

It inspects npm, pnpm, and bun installs and project upgrades for suspicious file reads, writes, process execution, and network behavior.

Use `goaudit scan` to audit a single npm, pnpm, or bun install command. Use `goaudit scan-project` to audit a JavaScript project before upgrading dependencies.

## Install

```zsh
go install github.com/KushalMeghani1644/GoAudit-CLI/cmd/goaudit@latest
```

## Usage

### Scan a command

Audit one npm, pnpm, or bun install command inside a Docker sandbox with strace tracing. Other ecosystems and arbitrary shell commands are rejected.

```zsh
goaudit scan "npm install lodash"
goaudit scan "pnpm add <package>"
goaudit scan "bun add <package>"
```

Common flags (both `scan` and `scan-project` unless noted):

| Flag | Purpose |
|------|---------|
| `--ci` | JSON output for CI |
| `--verbose` | Live findings during the scan |
| `--offline` | Skip host-side npm registry requests |
| `--network auto\|on\|off` | Sandbox network policy (see [Network policy](#network-policy)) |
| `--skip-probe` | Skip the post-install runtime probe |
| `--fail-on` | Exit non-zero on `malicious`, `inconclusive`, or both (default: `never`) |
| `--warm-cache` | Prepare the sandbox without running a scan |
| `--no-cache` | Do not store a warm container after this run |
| `--timeout` | Max time for the install command |
| `--probe-timeout` | Max time for the runtime probe (default: 30s) |
| `--mount-cwd` | `scan` only: allow mounting CWD for multi-local package installs |

```zsh
goaudit scan "npm install <package>" --ci --fail-on malicious,inconclusive
goaudit scan "npm install <package>" --verbose --offline
goaudit scan "npm install <package>" --network off
```

### Scan a project

`scan-project` audits an existing JavaScript project before you upgrade dependencies. It reads `package.json`, detects npm/pnpm/bun, checks dependencies against the npm registry, and then runs the upgrade install inside a sandbox. Your host `node_modules` is not modified.

Default upgrade mode is `refresh-lock`.

```zsh
goaudit scan-project ~/mywebsite
goaudit scan-project ~/mywebsite --upgrade-mode ncu
goaudit scan-project ~/monorepo --upgrade-mode update --ci
goaudit scan-project ~/app --manager pnpm
goaudit scan-project ~/app --include-transitive
goaudit scan-project ~/app --probe-all
goaudit scan-project ~/app --skip-probe
goaudit scan-project ~/app --mount-project
```

Upgrade modes:

| Mode | Behavior |
|------|----------|
| `refresh-lock` | Remove lockfile and reinstall (default) |
| `ncu` | Run npm-check-updates, then install (`bun` uses `bun update`) |
| `update` | Run the package manager's update command |

Project-only flags:

| Flag | Purpose |
|------|---------|
| `--upgrade-mode` | `refresh-lock`, `ncu`, or `update` |
| `--manager` | Force `npm`, `pnpm`, or `bun` |
| `--include-transitive` | Also registry-check packages listed in the manager's lockfile (`package-lock.json`, `pnpm-lock.yaml`, or `bun.lock`) |
| `--probe-all` | Probe all direct dependencies at runtime, not only suspicious ones |
| `--mount-project` | Stage the full project tree (secret paths redacted) instead of manifests/lockfiles only |

### Package manager support

| Manager | `scan` | `scan-project` |
|---------|--------|----------------|
| npm | Yes | Yes |
| pnpm | Yes | Yes |
| bun | Yes | Yes |
| pip | No | No |
| yarn | No | No |
| Arbitrary shell commands | No | No |

**npm, pnpm, and bun** get the full workflow: npm registry metadata checks, sandbox install tracing, and a Node runtime probe after install.

**yarn** is not supported. There is no Yarn sandbox profile, so `goaudit scan yarn install` will not run a meaningful install. Yarn projects (`yarn.lock`) are rejected by `scan-project`. Convert to npm, pnpm, or bun if you need project-level scanning.

### Network policy

`--network` controls sandbox network access and (together with `--offline`) host-side npm registry requests.

With `--network auto` (default):

| Profile | Sandbox network |
|---------|-------------------|
| npm, pnpm, bun | On |

Use `--network on` or `--network off` to override. Combine with `--offline` to block host-side fetches even when the sandbox has network access.

### Runtime probe

After a JavaScript install, GoAudit optionally loads each package entrypoint (`require` / dynamic `import`) and runs package CLI `bin` entries with `--help` under strace. This applies to npm, pnpm, and bun only.

| Command | Default probe scope |
|---------|---------------------|
| `scan` | Packages named in the install command |
| `scan-project` | Packages with suspicious registry findings only |

Use `--probe-all` with `scan-project` to probe every direct dependency. Use `--skip-probe` to disable probing.

The probe does **not** exercise delayed timers, workers, interactive prompts, or arbitrary exported APIs.

### Project staging

`scan-project` stages install inputs (manifests/lockfiles) into the sandbox by default so install scripts cannot read host secrets via `/project-ro`. Pass `--mount-project` for a full-tree stage with known secret paths redacted.

For `scan`, multi-local package installs refuse mounting the working directory unless `--mount-cwd` is set.

## Cache

GoAudit caches prepared sandbox containers to speed up repeat scans.

```zsh
goaudit cache status
goaudit cache clean
goaudit cache clean --runtime runsc
goaudit cache clean --runtime runc
```

Use `--cache-dir` or `GOAUDIT_CACHE_DIR` to store cache entries elsewhere. Target commands and runtime probes always execute as an unprivileged sandbox user.

## Requirements

- Docker
- gVisor (recommended)

### gVisor (runsc) on Fedora / SELinux

GoAudit uses gVisor when Docker lists `runsc` in `docker info` runtimes. Installing the `runsc` binary is not enough; it must be registered with Docker:

```json
{
  "runtimes": {
    "runsc": {
      "path": "/usr/local/bin/runsc",
      "runtimeArgs": ["--debug=false", "--platform=ptrace"]
    }
  },
  "default-runtime": "runc"
}
```

Use `runsc help platform` to see valid `--platform` values.

Restart Docker: `sudo systemctl restart docker`, then verify:

```bash
docker info | rg -i runtimes
```

**SELinux:** gVisor cannot use Docker's default container SELinux labels. GoAudit sets `--security-opt label=disable` automatically for `runsc` containers.

**Node sandbox image:** when gVisor is available and you keep the default `--node-image`, GoAudit uses `ghcr.io/kushalmeghani1644/goaudit-node-sandbox:latest` for Node-based scans.

**Fallbacks:** if gVisor is unavailable, or image preparation fails, GoAudit falls back to `runc` and prints a warning.

## Limitations

GoAudit provides a risk assessment based on behavior and static indicators. It is not meant to prove absolute maliciousness.

Other documented limits:

- Package commands are not fully shell-parsed (pipes, substitutions, and complex wrappers may be incomplete).
- Secret redaction under `--mount-project` covers common paths, not every possible secret filename.
- Private registry auth is not used for host-side static analysis.
- Semver ranges may resolve to registry "latest" with an approximate-version finding.
