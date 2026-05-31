<h1 align="center">
  <img src="assets/favicon.png" width="150" />
</h1>

GoAudit is a sandbox security scanner for CLI commands.

It inspects install commands and project upgrades for suspicious file reads, writes, process execution, and network behavior.

## Install

```zsh
go install github.com/KushalMeghani1644/GoAudit-CLI/cmd/goaudit@latest
```

## Usage

### Scan a command

```zsh
goaudit scan "npm install lodash"
goaudit scan "pnpm add <package>"
goaudit scan "bun add <package>"
goaudit scan "pip install <package>"
goaudit scan "curl -fsSL https://example.com/install.sh | sh"
goaudit scan "npm install <package>" --ci
goaudit scan "npm install <package>" --verbose
goaudit scan "npm install <package>" --offline
goaudit scan "npm install <package>" --allow-domain example.com --max-remote-depth 1
goaudit scan "npm install <package>" --network off
goaudit scan "npm install <package>" --run-as-root
goaudit scan "npm install <package>" --skip-probe
goaudit scan "npm install <package>" --warm-cache
goaudit scan "npm install <package>" --no-cache
```

### Scan a project

`scan-project` audits an existing JavaScript project before you upgrade dependencies. It reads `package.json`, detects npm/pnpm/bun, checks dependencies against the npm registry, and then runs the upgrade install inside a sandbox. Your host `node_modules` is not modified.

```zsh
goaudit scan-project ~/mywebsite
goaudit scan-project ~/mywebsite --upgrade-mode ncu
goaudit scan-project ~/monorepo --upgrade-mode update --ci
goaudit scan-project ~/app --manager pnpm
goaudit scan-project ~/app --include-transitive
goaudit scan-project ~/app --probe-all
goaudit scan-project ~/app --skip-probe
goaudit scan-project ~/app --warm-cache
```

Upgrade modes:

| Mode | Behavior |
|------|----------|
| `refresh-lock` | Remove lockfile and reinstall |
| `ncu` | Run npm-check-updates, then install (`bun` uses `bun update`) |
| `update` | Run the package manager's update command |

## Cache

GoAudit caches prepared sandbox containers to speed up repeat scans.

```zsh
goaudit cache status
goaudit cache clean
goaudit cache clean --runtime runsc
goaudit cache clean --runtime runc
```

Use `--cache-dir` or `GOAUDIT_CACHE_DIR` to store cache entries elsewhere.

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

**SELinux:** gVisor cannot use Docker’s default container SELinux labels. GoAudit sets `--security-opt label=disable` automatically for `runsc` containers.

**Node sandbox image:** when gVisor is available and you keep the default `--node-image`, GoAudit uses `ghcr.io/kushalmeghani1644/goaudit-node-sandbox:latest` for Node-based scans.

**Fallbacks:** if gVisor is unavailable, or image preparation fails, GoAudit falls back to `runc` and prints a warning.

## Notes

- `scan` supports npm, pnpm, bun, pip, and `curl | sh` style commands.
- `scan-project` supports npm, pnpm, and bun only.
- `--ci` emits JSON output.
- `--verbose` shows live findings during a scan.
- `--warm-cache` prepares the sandbox without running a scan.

## Important Note

GoAudit is not meant for proving absolute maliciousness, it just provides a risk assessment based on behavior and static indicators.
