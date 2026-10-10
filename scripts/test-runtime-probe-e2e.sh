#!/usr/bin/env bash
set -euo pipefail

CLI=${GOAUDIT_BIN:-./goaudit}
IMAGE=${GOAUDIT_NODE_IMAGE:-goaudit-node-sandbox:ci}
FIXTURES=${GOAUDIT_RUNTIME_FIXTURES:-testdata/runtime-probe}

run_fixture() {
  local fixture=$1
  local mode=$2
  local output
  local -a probe_flags=()
  local -a scan_command=(
    scan "npm install --userconfig=/dev/null --offline --no-audit --no-fund ./$FIXTURES/$fixture"
  )
  if [[ "$mode" != off ]]; then
    probe_flags+=(--runtime-probe)
  fi
  if [[ "$mode" == continuation ]]; then
    # Stage just this fixture's tree so its contained file: dependencies exist.
    scan_command=(scan-project "$FIXTURES/$fixture" --manager=npm --mount-project)
  fi

  output=$(mktemp)
  trap 'rm -f "$output"' RETURN
  # Never import fixture code on the host. GoAudit stages this one fixture and
  # executes it with synthetic credentials under its required runsc runtime.
  "$CLI" "${scan_command[@]}" \
    --ci \
    --no-cache \
    --offline \
    --network=off \
    --fail-on=never \
    --probe-timeout=10s \
    --node-image="$IMAGE" \
    "${probe_flags[@]}" >"$output"

  python3 - "$output" "$fixture" "$mode" <<'PY'
import json
import sys

path, fixture, mode = sys.argv[1:]
with open(path, encoding="utf-8") as report_file:
    report = json.load(report_file)

observations = [
    observation
    for signal in report["signals"]
    for observation in signal["observations"]
]
diagnostics = report.get("diagnostics") or []
meta = report.get("meta") or {}

def fail(message):
    raise SystemExit(f"{fixture} ({mode}): {message}\n{json.dumps(report, indent=2)}")

def require(condition, message):
    if not condition:
        fail(message)

def diagnostic(name):
    # Raw markers are GOAUDIT_PROBE_*; report reason codes omit GOAUDIT_.
    return [
        entry for entry in diagnostics
        if entry.get("reasonCode", "").removeprefix("GOAUDIT_") == "PROBE_" + name
    ]

def diagnostic_text(entries):
    return " ".join(json.dumps(entry, sort_keys=True) for entry in entries).lower()

def observations_with_reason(name):
    return [entry for entry in observations if entry.get("reasonCode") == name]

require(meta.get("sandboxRuntime") == "runsc", "scan did not report runsc isolation")
dynamic = meta.get("dynamic") or {}
target = dynamic.get("target") or {}
probe = dynamic.get("probe") or {}
require(target.get("exitObserved") and target.get("exitCode", 0) == 0,
        "fixture install did not complete successfully")
credentials = [entry for entry in observations if entry.get("reasonCode") == "CREDENTIAL_READ"]

if mode == "off":
    # Registry-only flags can make an offline fixture SUSPICIOUS. They do not
    # prove runtime behavior, and must not mask a missing/failed install.
    require(report["verdict"] in ("CLEAN", "SUSPICIOUS"),
            "default-off install was malicious or inconclusive")
    require(not credentials, "credential read occurred with runtime probe omitted")
    require(not probe.get("expected") and not probe.get("phaseObserved"),
            "runtime probe ran without explicit opt-in")
    require(not any(entry.get("reasonCode", "").startswith(("PROBE_", "GOAUDIT_PROBE_"))
                    for entry in diagnostics),
            "default-off scan contains runtime-probe diagnostics")
else:
    require(probe.get("expected") and probe.get("phaseObserved"),
            "opt-in runtime probe was not observed")
    require(diagnostic("COVERAGE"), "missing runtime coverage diagnostic")
    if mode == "hanging":
        require(report["verdict"] == "INCONCLUSIVE",
                "hanging import must be inconclusive, not clean")
        require(diagnostic("PACKAGE_TIMEOUT"), "missing package-timeout diagnostic")
        require(not credentials, "hanging-only fixture unexpectedly read credentials")
    else:
        require(report["verdict"] == "MALICIOUS", "opt-in read must be malicious")
        require(any("[runtime probe]" in entry.get("evidence", "")
                    and ".aws/credentials" in (entry.get("path", "") + entry.get("evidence", ""))
                    for entry in credentials),
                "missing AWS CREDENTIAL_READ with [runtime probe] evidence")
        require(diagnostic("OBSERVATION_COMPLETE"),
                "missing delayed-observation completion diagnostic")
        require("complete" in diagnostic_text(diagnostic("COVERAGE")),
                "coverage does not declare a completed package")
        if fixture == "api-lodash":
            api = diagnostic("API_OK")
            require(api and "lodash" in diagnostic_text(api) and "chunk" in diagnostic_text(api),
                    "missing successful lodash.chunk adapter diagnostic")
        if fixture == "obfuscated":
            require(observations_with_reason("PROBE_OBFUSCATION"),
                    "missing obfuscation signal")
            require(diagnostic("SOURCE_SCAN"), "missing installed-source scan diagnostic")
        if mode == "continuation":
            require("aaa-goaudit-test-hanging" in diagnostic_text(diagnostic("PACKAGE_TIMEOUT")),
                    "missing first dependency's package-timeout diagnostic")
            require("zzz-goaudit-test-following" in diagnostic_text(diagnostic("IMPORT_OK")),
                    "package after hanging dependency was not imported")
            require("zzz-goaudit-test-following" in
                    diagnostic_text(diagnostic("OBSERVATION_COMPLETE")),
                    "following package's observation window did not complete")

print(f"PASS {fixture}: {mode} ({report['verdict']})")
PY
}

for fixture in import-time delayed esm api-lodash obfuscated hanging; do
  run_fixture "$fixture" off
  if [[ "$fixture" == hanging ]]; then
    run_fixture "$fixture" hanging
  else
    run_fixture "$fixture" on
  fi
done

run_fixture hang-then-next continuation
