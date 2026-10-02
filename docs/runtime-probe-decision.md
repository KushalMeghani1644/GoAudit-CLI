# KUS-54: retain runtime probing as explicit bounded sampling

## Decision

Keep and improve the runtime probe, but require `--runtime-probe` on both
`scan` and `scan-project`. Default scans retain static/registry analysis and
sandbox install tracing. They do not load packages after installation.

Removal would lose detection of import-time and CLI-startup payloads in
packages that install quietly. Retaining automatic probing would impose extra
untrusted execution, latency, and generic-harness incompatibilities on every
selected install. Explicit enablement preserves the useful signal without
making it an implicit safety guarantee.

Project opt-in exercises all direct manifest dependencies, not just packages
already flagged by registry checks. Transitive static checks do not expand
runtime selection. Packages can naturally load their own dependencies.

Compatibility: `--skip-probe` is a deprecated default-off no-op, contradictory
true enable/skip flags are rejected, `--probe-all` is removed, and
`--probe-timeout` remains the shared deadline. Consumers must opt in explicitly
if their automation previously relied on automatic probing.

## Meaningful, bounded coverage

- CommonJS/ESM initialization runs in a separate process per package.
- Known `lodash`, `yaml`, `minimist`, and `marked` adapters exercise deterministic
  benign inputs; there is no speculative arbitrary-export invocation.
- Real timers are observed for one second after import/API work if budget
  permits; timers are not accelerated or rewritten.
- Declared bins run with `--help` even when imports fail or hang. Absolute,
  traversal, non-file, and symlink-escaping bin paths are rejected.
- Controller-owned process groups are cleaned on early exit and timeout.
  Deliberately escaped sessions are outside this guarantee; gVisor and
  container cleanup remain the boundary.
- Up to 256 KiB of one resolved JS entrypoint is inspected for nearby
  decode-to-execute composites. Source indicators are warnings, not malware
  proof, and may flag comments, strings, or unrelated operations. No recursive
  analysis or deobfuscation is claimed.
- Per-exercise diagnostics expose incomplete coverage. Runtime incompatibility
  produces `INCONCLUSIVE`, not a malware classification. Actual malicious
  observations take precedence and install evidence remains available.

Unsupported APIs and unresolved import-only source entrypoints are explicitly
reported. A "complete" package diagnostic means the selected exercises
completed, not that every application path or source file was tested.

## Real sandbox evidence

The runtime fixture suite runs untrusted fixtures only inside gVisor with
synthetic credentials and networking disabled:

- Import-time, ESM, 200 ms delayed, supported-API, and obfuscated credential
  reads: default-off `CLEAN`; opt-in `MALICIOUS` with probe-phase
  `CREDENTIAL_READ`.
- Hanging-only import: default-off `CLEAN`; opt-in `INCONCLUSIVE`.
- Hanging dependency followed by a credential-reading dependency: later
  package still executes, and the malicious evidence wins over the timeout.

Reproduce with `scripts/test-runtime-probe-e2e.sh`. These fixtures demonstrate
the detection capability retained by the opt-in design. They must not be
imported directly on the host.

## Benchmark

Whole-CLI wall time on x86_64 under `runsc`, three samples per mode/cache path,
with reversed pair order on the second repetition:

```text
npm install lodash@4.17.21 yaml@2.8.1 minimist@1.2.8 marked@15.0.12
```

Same image for all runs:

```text
ghcr.io/kushalmeghani1644/goaudit-node-sandbox@sha256:733526e086a8dfe471960639ab5e8b8dc258edf9120860785e931f2c15276b42
```

| Path | Mode | Samples (seconds) | Mean | Median |
|------|------|-------------------|------|--------|
| Fresh | Default/off | 26.740, 25.612, 26.561 | 26.304 | 26.561 |
| Fresh | Opt-in | 35.230, 33.882, 34.729 | 34.614 | 34.729 |
| Cached | Default/off | 28.572, 29.155, 28.750 | 28.826 | 28.750 |
| Cached | Opt-in | 37.167, 37.484, 36.775 | 37.142 | 37.167 |

All 12 runs returned `CLEAN`, with complete required phase/exit/syscall
evidence. Every opt-in run exercised all four adapters, observed all four
windows, and completed the YAML/marked bin exercises. Security signal types
were unchanged: registry connections and the generic lifecycle-script notice.
Connection counts and registry IPs naturally varied.

The opt-in exercises added about **8.31 seconds** in either path. These are
small-sample, network-dependent workflow measurements, not universal overhead
estimates or isolated probe timings. Cached wall time includes automatic
replacement-cache preparation; its pre-run warm-up is excluded. Thus this
experiment is not evidence that caching universally speeds up whole commands.

Reproduce using `python3 scripts/benchmark-runtime-probe.py --cli ./goaudit
--image <pinned-image> --output <new-report-directory> --samples 3`. The script
retains JSON reports and timings and rejects failed/inconclusive samples.

The original default Node image failed to start under this machine's gVisor
with an `exec format error`; the verified GoAudit image above was used for
both modes. This experiment does not establish the cause of that image failure.

## Website coordination

Website source is not part of this repository or the attached workspace.
Update its CLI examples and feature descriptions to match the opt-in default,
coverage, and limitations before marking the website acceptance criterion
complete. No website update is claimed by this PR.
