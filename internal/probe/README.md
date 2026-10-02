# Opt-in Node runtime probe

`GenerateNodeProbeScript` embeds `node_probe.cjs` as a CommonJS controller.
The caller must run the generated shell **inside the audit sandbox** and preserve
its exit status. This probe executes untrusted code; it is not itself a security
boundary or a comprehensive malware detector.

## Execution and budgets

The controller only resolves package roots, reads bounded regular-file
manifests, scans the entrypoint, and schedules workers. It never imports package
code. Each package import/API worker and each declared CLI bin runs in its own
detached process group. The controller SIGKILLs that group on timeout **and**
on normal/early exit, so inherited grandchildren cannot outlive the attempt.
Bins remain reachable if the import fails, exits, or hangs.

A whole-probe deadline reserves up to one second (at most a quarter of the
budget) for cleanup and reporting before the sandbox's outer timeout, which
starts before Node initialization. The remainder is divided fairly among
remaining packages. A package
with bins reserves half of its remaining budget for importing/exercising/
observing, and divides the remainder among its bins. Unused time can benefit
later work. A shell watchdog adds a two-second controller grace period and a
one-second SIGKILL fallback. Actual budget exhaustion exits 124; unexpected
controller errors exit 1. Import/API incompatibilities and unsuccessful bins
are coverage diagnostics, not malware verdicts, and do not alone fail the phase.

The import worker uses require then dynamic import, supports workspace ESM,
and does not hide a broken declared workspace main behind index fallback.
After loading and the allowlisted API exercise, it observes real timers for
one second when budget permits. Shorter observations are explicitly incomplete.
The only adapters are exact `lodash.chunk([1,2,3],2)`,
`yaml.parse('goaudit: true')`, `minimist(['--goaudit','true'])`, and
`marked.parse('# GoAudit')`, including ESM default interop. API shape is checked
and async completion is bounded externally. Other exports are never called.
Bins receive only `--help`; arbitrary CLI commands, arguments, and persistent
post-exit CLI observation are not covered.

Declared bins must be relative paths with no traversal. Their realpaths must
remain inside the real resolved package root. Absolute, traversal, missing,
non-file, and symlink-escape entries fail without execution.

## Markers

Markers are emitted on stderr. Package and bin labels retain their existing
colon-separated representation (including scoped package names).

| Marker | Meaning |
| --- | --- |
| `GOAUDIT_PROBE_IMPORT_OK:<pkg>` | require or ESM import completed |
| `GOAUDIT_PROBE_IMPORT_FAILED:<pkg>:<reason>` | import failed, exited early, or timed out |
| `GOAUDIT_PROBE_API_OK:<pkg>:<adapter>` | allowlisted call completed |
| `GOAUDIT_PROBE_API_FAILED:<pkg>:<adapter>:<reason>` | call threw/rejected/exited/timed out |
| `GOAUDIT_PROBE_API_UNSUPPORTED:<pkg>[:<adapter>]` | no allowlisted adapter or expected API absent |
| `GOAUDIT_PROBE_BIN_OK:<pkg>:<declared>` | help command exited normally with code 0 |
| `GOAUDIT_PROBE_BIN_FAIL:<pkg>:<declared>:<reason>` | unsafe/missing path or command failure |
| `GOAUDIT_PROBE_PACKAGE_TIMEOUT:<pkg>:import\|api\|observation\|bin` | package phase exhausted its budget |
| `GOAUDIT_PROBE_OBSERVATION_COMPLETE:<pkg>:1000ms` | full post-import/API window completed |
| `GOAUDIT_PROBE_OBSERVATION_INCOMPLETE:<pkg>:budget\|timeout\|worker_exit` | observation shorter or interrupted |
| `GOAUDIT_PROBE_COVERAGE:<pkg>:complete\|incomplete` | attempted supported work completed, or had gaps |
| `GOAUDIT_PROBE_SOURCE_SCAN:<pkg>:complete\|unsupported\|truncated\|failed` | bounded entrypoint scan diagnostic |
| `GOAUDIT_PROBE_OBFUSCATION:<pkg>:decode_to_execute` | suspicious nearby decoding and execution source composite |
| `GOAUDIT_PROBE_TIMEOUT` | at least one deadline exhausted; phase exits 124 |
| `GOAUDIT_PROBE_ERROR:<reason>` | unexpected controller failure |
| `GOAUDIT_PROBE_LIMITATION:allowlisted_api_and_bin_help_only` | reminder of bounded exercise scope |

Complete coverage means completion of these limited attempts, not exhaustive
coverage or proof of safety. Unknown-package unsupported adapters are expected,
not by themselves gaps. Too little observation time marks coverage incomplete
even when the phase exits normally.

## Source indicator and limitations

Source scanning reads at most 256KiB of a single resolved JS/CJS/MJS entrypoint.
It flags `eval(...)` or `new Function(...)` within 512 characters of
`Buffer.from(..., 'base64').toString(...)` or `atob(...)`. Standalone decoding,
standalone eval, and minification are not indicators. This heuristic does not
parse JavaScript; dead code, comments, strings, or unrelated nearby operations
can cause a warning. It does not traverse dependencies or deobfuscate/execute
payloads. Import-only resolution that Node's require resolver cannot locate
is reported unsupported, even if runtime ESM loading works.

Process groups clean descendants that inherit the worker's group. Deliberately
detached children, session escapes, killing the controller, monkeypatching
worker reporting, marker spoofing, filesystem races, and other hostile actions
require the sandbox/cgroup boundary. Path validation is not a race-proof
replacement for sandbox containment. Node initialization and controller startup
add overhead outside the internal deadline, bounded by the shell watchdog.
