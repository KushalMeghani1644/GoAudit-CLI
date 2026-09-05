## Audit Findings — Remediation Status

Living tracker for the audit findings. Status reflects the current working tree.

### Critical

| Finding | Status | Notes |
|---------|--------|-------|
| scan-project exposes project via `/project-ro` | **Fixed** | `project.StageForSandbox` minimal/full redacted stage; default minimal; `--mount-project` / `--mount-cwd` opt-in |
| Remote-script host-side SSRF | **Fixed** | Public-IP dial, redirect re-check, metadata/RFC1918 blocks; `--network off` / `--offline` gate host static fetches |
| Benign `/etc/passwd` → MALICIOUS | **Fixed** | Parser skips RO passwd; not hard-malicious by reason alone |
| Cache network policy mismatch | **Fixed** | Warm create passes `NetworkEnabled`; cache validates live network mode |
| DATA_EXFIL without proof of send | **Fixed** | Hard exfil only after sendto/sendmsg/sendmmsg/sendfile/splice; else `CREDENTIAL_READ_WITH_OUTBOUND` |

### High

| Finding | Status | Notes |
|---------|--------|-------|
| Registry analyzes wrong version | **Mostly fixed** | Concrete versions + dist-tags; ranges fall back to latest with `VERSION_RESOLUTION_APPROXIMATE`; lockfiles feed `name@version` |
| Silent 3-package static cap | **Fixed** | Cap 25 + `STATIC_COVERAGE_LIMIT` finding |
| Package-command not shell parsing | **Improved** | Wrappers (sudo/env/corepack/timeout/nice/…), quote strip; `PACKAGE_PARSE_INCOMPLETE` for pipes/substitutions; not a full shell parser |
| Incomplete dynamic tracing / rename dest | **Mostly fixed** | rename dest + renameat2/link/mkdir/setuid family; added truncate/chown/mount/umount2/capset/sendfile/splice |
| Cached sandboxes not reset | **Fixed** | `resetMutableStateScript` wipes home/tmp/caches before each warm scan |
| Mutable images / pnpm@latest | **Improved** | Floating tags (`:latest`, `:current-slim`, …) always re-pulled; pnpm pinned to `9.15.9` |

### Coverage Gaps / Misleading Behavior

| Finding | Status | Notes |
|---------|--------|-------|
| Transitive only npm lockfile | **Fixed** | npm + pnpm + bun.lock; bun.lockb unsupported warning; workspaces; flag help updated |
| Runtime probe shallow | **Improved** | Import/require + bin `--help`; `PROBE_LIMITATION` finding; README documents limits |
| Yarn project profile missing | **Fixed (honest)** | `scan-project` has no Yarn profile; generic `scan` can audit an explicit Yarn command. README states the scoped limitation. |
| Script lowercased before hash | **Fixed** | Remote hash uses original bytes; local lifecycle no longer lowercases body |
| `--offline` / `--network off` host fetches | **Fixed** | Registry + remote scripts gated by `hostStaticNetwork` |
| `--fail-on` typo → never fail | **Fixed** | `validateFailOn` rejects unknown values |

### Residual risks (documented non-goals)

- Full shell AST / command substitution evaluation
- Perfect secret redaction for custom secret filenames under `--mount-project`
- Private registry auth for static analysis
- Exhaustive runtime API fuzzing / delayed malware paths
- Semver range resolution without registry “latest” fallback (emits approximate finding)

### Verification

- Unit tests: cmd, analyzer, parser, project, report, sandbox, probe, diagnostic
- Race tests on critical packages
- Docker E2E not run in environments without Docker socket access

Recommended next steps for maintainers: commit this remediation batch; optional follow-ups = true semver range matcher, yarn profile if product wants it, docker-commit snapshot restore if warm-root ever needed.
