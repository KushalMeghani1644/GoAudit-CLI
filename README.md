<h1 align="center">
  <img src="assets/favicon.png" width="150" />
</h1>

GoAudit is a sandbox security scanner for JavaScript package installs.

It inspects npm, pnpm, and bun installs and project upgrades for suspicious file reads, writes, process execution, and network behavior.

Use `goaudit scan` to audit a single npm, pnpm, or bun install command. Use `goaudit scan-project` to audit a JavaScript project before upgrading dependencies.

## Demo

Representative output with runtime probing explicitly enabled in a gVisor (`runsc`) sandbox (exact findings and counts vary by run):

```zsh
goaudit scan "npm install lodash@4.17.21" --runtime-probe
```

```text
GoAudit Report
────────────────────────────────────────────────────────────────
Command: npm install lodash@4.17.21
Verdict: CLEAN
Sandbox: gVisor (runsc)

Signals
   network-exfil
      - network-connection: EXTERNAL_NETWORK_REGISTRY: registry.npmjs.org
   suspicious-registry
      - registry-metadata-flag: NPM_LIFECYCLE_SCRIPTS: npm install lodash@4.17.21

What GoAudit Observed
   1. GoAudit installed and observed the target in a sandbox.
   2. It did not observe credential reads, persistence writes, suspicious process execution, or unexpected outbound network connections.
Runtime Probe
   - No suspicious behavior observed in bounded runtime exercises
   - PROBE_SOURCE_SCAN: lodash:truncated
   - PROBE_IMPORT_OK: lodash
   - PROBE_API_OK: lodash:chunk
   - PROBE_OBSERVATION_COMPLETE: lodash:1000ms
   - PROBE_COVERAGE: lodash:complete
   - Sampling is not a safety guarantee: arbitrary APIs, long delays, and application-specific paths remain untested

Static Warnings
────────────────────────────────────────────────────────────────
   1. [WARNING] LIFECYCLE SCRIPTS: npm install lodash@4.17.21
      Details: npm install runs lifecycle scripts (preinstall/postinstall) — this is common

Network Activity (expected)
   - 1 connection(s) to registry.npmjs.org (registry)
   - 1 connection(s) to 1 host(s)
Summary: 0 critical (0 install-time, 0 probe, 0 static), 1 warnings, 17 informational
   Use --ci for full JSON output.
```

The observed verdict for `lodash` is clean here: the single warning is the expected npm lifecycle-scripts notice and only registry network traffic was observed. This is not a guarantee that every import or application path is safe. The registry connection may also show a resolved IP address in the report.

With `--ci`, the same evidence is emitted as stable signal categories and raw observations rather than
an opaque numeric confidence score. The CI report also includes runtime diagnostics and metadata; the
example below shows the stable signal portion (resolved IPs and tool versions vary by run):

```json
{
  "verdict": "CLEAN",
  "signals": [
    {
      "category": "network-exfil",
      "observations": [
        {
          "kind": "network-connection",
          "severity": "INFO",
          "reasonCode": "EXTERNAL_NETWORK_REGISTRY",
          "host": "registry.npmjs.org",
          "port": 443,
          "evidence": "[install]"
        }
      ]
    },
    {
      "category": "suspicious-registry",
      "observations": [
        {
          "kind": "registry-metadata-flag",
          "severity": "WARNING",
          "reasonCode": "NPM_LIFECYCLE_SCRIPTS",
          "path": "npm install lodash@4.17.21",
          "evidence": "npm install may execute lifecycle scripts (preinstall/install/postinstall)"
        }
      ]
    }
  ]
}
```

Signals are grouped by behavior: `credential-access`, `persistence`, `network-exfil`,
`privilege-escalation`, `execution`, and `suspicious-registry`. Each observation retains its
severity, reason code, and relevant path, host, or evidence.

## Install

**Homebrew** (macOS and Linux):

```zsh
brew install --cask KushalMeghani1644/tap/goaudit
```

**mise**:

```zsh
mise use -g github:KushalMeghani1644/GoAudit-CLI
```

**Go**:

```zsh
go install github.com/KushalMeghani1644/GoAudit-CLI/cmd/goaudit@latest
```

## Usage

### Scan a command

Audit one npm, pnpm, or bun install command inside a Docker sandbox with strace tracing. Other ecosystems and arbitrary shell commands are rejected.

GoAudit requires Docker to have the gVisor `runsc` runtime registered. It refuses to run when `runsc` is not registered with Docker.

```zsh
goaudit scan "npm install lodash"
goaudit scan "pnpm add <package>"
goaudit scan "bun add <package>"
goaudit scan "npm install lodash" --runtime-probe
```

By default, GoAudit performs static checks and traces the sandbox install, including lifecycle scripts. Post-install runtime probing is **off by default**; opt in with `--runtime-probe`.

Common flags (both `scan` and `scan-project` unless noted):

| Flag | Purpose |
|------|---------|
| `--ci` | JSON output for CI |
| `--verbose` | Live findings during the scan |
| `--offline` | Skip host-side npm registry requests |
| `--network auto\|on\|off` | Sandbox network policy (see [Network policy](#network-policy)) |
| `--runtime-probe` | Opt in to post-install runtime probing (default: off) |
| `--skip-probe` | Deprecated compatibility no-op; probing is already off by default |
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
goaudit scan-project ~/app --runtime-probe
goaudit scan-project ~/app --include-transitive --runtime-probe
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
| `--include-transitive` | Also registry-check packages listed in the manager's lockfile (`package-lock.json`, `pnpm-lock.yaml`, or `bun.lock`); does not expand runtime probe scope |
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

**npm, pnpm, and bun** get npm registry metadata checks and sandbox install tracing, plus an optional Node runtime probe after install when `--runtime-probe` is enabled.

**yarn** is not supported. There is no Yarn sandbox profile, so `goaudit scan yarn install` will not run a meaningful install. Yarn projects (`yarn.lock`) are rejected by `scan-project`. Convert to npm, pnpm, or bun if you need project-level scanning.

### Network policy

`--network` controls sandbox network access and (together with `--offline`) host-side npm registry requests.

With `--network auto` (default):

| Profile | Sandbox network |
|---------|-------------------|
| npm, pnpm, bun | On |

Use `--network on` or `--network off` to override. Combine with `--offline` to block host-side fetches even when the sandbox has network access.

### Runtime probe

Runtime probing is **off by default** for both scan commands. Pass `--runtime-probe` to request a post-install probe under strace. This applies to npm, pnpm, and bun installs; the probe uses Node, not Bun's native runtime.

The controller exercises each selected package in an isolated Node process, loading its entrypoint (`require` / dynamic `import`). It also runs declared CLI `bin` entries with `--help`, rejecting paths outside the package root. A one-second post-load observation window allows short delayed behavior to execute naturally when the timeout budget permits.

Known packages get deterministic API exercises; arbitrary exports are never called:

| Package | API exercise |
|---------|--------------|
| lodash | `chunk([1, 2, 3], 2)` |
| yaml | `parse("goaudit: true")` |
| minimist | Parse `["--goaudit", "true"]` |
| marked | `parse("# GoAudit")` |

The probe also inspects up to 256 KiB of a resolved JavaScript entrypoint for nearby decode-to-execute patterns (base64/`atob` with `eval`/`new Function`). These are suspicious indicators, **not proof of malware**. This heuristic can flag comments, strings, or unrelated nearby operations; it is not a recursive source scan or deobfuscator. Import-only entrypoints that cannot be resolved for inspection are reported as unsupported.

| Command | Scope with `--runtime-probe` |
|---------|---------------------|
| `scan` | Packages named in the install command |
| `scan-project` | All direct dependencies from project manifests, including development, optional, and workspace package dependencies |

Project probing is not restricted to packages with suspicious registry findings. `--include-transitive` expands **static registry checks only**, not runtime probing. Neither command automatically probes all transitive dependencies; a selected package can still load its own dependencies during execution. A command such as `scan "npm install"` names no packages and therefore selects none for probing.

Compatibility: `--probe-all` has been removed and is an unknown flag; replace it with `--runtime-probe`. `--skip-probe` remains accepted as a deprecated no-op so existing default-off invocations keep working. Passing both `--runtime-probe` and `--skip-probe` as true is an error; an explicit `--skip-probe=false` does not conflict.

`--probe-timeout` remains available (default: `30s`). One shared deadline is divided among selected packages and their exercises. A hanging package is terminated without preventing later packages from being attempted. Ordinary descendant process groups are cleaned up on exit and timeout; deliberately detached processes remain the sandbox's responsibility.

Human and JSON reports distinguish successful exercises, unsupported adapters, source inspection, and incomplete observation. Exercise failures or incomplete runtime coverage produce `INCONCLUSIVE`, unless observed malicious behavior takes precedence; install findings remain available. An unsupported adapter alone does not fail the scan.

Package installation, import, and CLI stdout/stderr are not parsed as diagnostics. Only controller records, restricted harness IPC diagnostics, and syscall evidence reach the report stream. This prevents package output from forging coverage or source-inspection records; it does not make the shared worker JavaScript realm tamper-proof.

Probing is bounded sampling, not a full application test: it cannot cover arbitrary exported APIs, interactive workflows, persistent CLI activity after exit, or all delayed activity. A clean probe does not establish that a package is safe, and default-off scans provide no post-install probe coverage. Install-time tracing still runs without this opt-in.

See [the KUS-54 decision and benchmark](docs/runtime-probe-decision.md) and [probe implementation notes](internal/probe/README.md).

### Project staging

`scan-project` stages install inputs (manifests/lockfiles) into the sandbox by default so install scripts cannot read host secrets via `/project-ro`. Pass `--mount-project` for a full-tree stage with known secret paths redacted.

For `scan`, multi-local package installs refuse mounting the working directory unless `--mount-cwd` is set.

## Cache

GoAudit caches prepared sandbox containers to speed up repeat scans. Each warm container is atomically claimed for one target, destroyed after that scan, and replaced with a clean container so target-mutated state is never reused.

```zsh
goaudit cache status
goaudit cache clean
```

Use `--cache-dir` or `GOAUDIT_CACHE_DIR` to store cache entries elsewhere. Target commands and runtime probes always execute as an unprivileged sandbox user.

## Requirements

- Docker
- gVisor (`runsc`) registered with Docker (required)

### gVisor (runsc) on Fedora / SELinux

GoAudit requires gVisor and exits with code 1 unless Docker lists `runsc` in `docker info` runtimes. Installing the `runsc` binary is not enough; it must be registered with Docker:

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

**Node sandbox image:** when you keep the default `--node-image`, GoAudit uses a digest-pinned, multi-platform `ghcr.io/kushalmeghani1644/goaudit-node-sandbox` image for Node-based scans.

GoAudit never falls back to `runc`. If runtime verification or sandbox preparation fails, the scan stops rather than silently weakening isolation.

## Limitations

GoAudit provides a risk assessment based on behavior and static indicators. It is not meant to prove absolute maliciousness.

Other documented limits:

- Package commands are not fully shell-parsed (pipes, substitutions, and complex wrappers may be incomplete).
- Secret redaction under `--mount-project` covers common paths, not every possible secret filename.
- Private registry auth is not used for host-side static analysis.
- Semver ranges may resolve to registry "latest" with an approximate-version finding.
