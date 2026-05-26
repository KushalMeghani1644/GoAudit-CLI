<h1 align="center">
  <img src="assets/favicon.png" width="150" />
</h1>

GoAudit is a utility for checking whether a npm install or a curl | sh is malicious or not?

## Demo

Using GoAudit is simple! just use the `scan` command and give the `npm install` or `curl | sh` command you want to check.

```zsh
$ goaudit scan "cat ~/.aws/credentials"
[CRITICAL] File Read: /root/.aws/credentials
Verdict: MALICIOUS

$ goaudit scan "npm install lodash"
[WARNING] Suspicious Command Pattern: npm install lodash
Verdict: SUSPICIOUS
```

## Install 

Currently to install GoAudit, you need to have Go installed on your system, with that just run the following command!

```zsh
go install github.com/KushalMeghani1644/GoAudit-CLI@latest
```

## Usage

GoAudit provides a simple UX for scanning npm, pnpm, bun, pip, and curl | sh commands. Currently we support these managers for checks, and project-based scans for JS apps.

### Scan a single command

```zsh
goaudit scan "npm install <package>"
goaudit scan "pnpm add <package>"
goaudit scan "bun add <package>"
goaudit scan "pip install <package>"
goaudit scan "curl -fsSL https://example.com/install.sh | sh"
goaudit scan "npm install <package>" --ci   # JSON output
goaudit scan "curl -fsSL https://example.com/install.sh | sh" --offline
goaudit scan "curl -fsSL https://example.com/install.sh | sh" --allow-domain example.com --max-remote-depth 1
goaudit scan "pnpm add <package>" --node-image node:current-slim
goaudit scan "bun add <package>" --bun-image oven/bun:1
goaudit scan "npm install <package>" --run-as-root
goaudit scan "npm install <package>" --skip-probe
goaudit scan "npm install <package>" --network off
```

### Scan a project directory

Audit an existing app (Next.js, TanStack, etc.) before upgrading dependencies. GoAudit reads `package.json`, detects npm/pnpm/bun, statically checks direct dependencies against the npm registry, then runs the upgrade install inside a sandbox. Your host `node_modules` is not modified.
```zsh
goaudit scan-project ~/mywebsite
goaudit scan-project ~/mywebsite --upgrade-mode ncu
goaudit scan-project ~/monorepo --upgrade-mode update --ci
goaudit scan-project ~/app --manager pnpm
goaudit scan-project ~/app --include-transitive   # also check package-lock.json packages
goaudit scan-project ~/app --probe-all            # probe all dependencies, not just suspicious ones
goaudit scan-project ~/app --skip-probe
```

| `--upgrade-mode` | Behavior |
|------------------|----------|
| `refresh-lock` (default) | Remove lockfile and reinstall (full re-resolve) |
| `ncu` | Run npm-check-updates, then install (`bun` uses `bun update`) |
| `update` | `npm update` / `pnpm update` / `bun update` |

## Requirements

- Docker
- gVisor (recommended)

## Important Note

GoAudit is not meant for proving absolute maliciousness, it just provides a risk assessment based on behavior and static indicators.
