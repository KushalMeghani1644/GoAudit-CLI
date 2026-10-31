#!/usr/bin/env bash
set -euo pipefail

CLI=${GOAUDIT_BIN:-./goaudit}
IMAGE=${GOAUDIT_NODE_IMAGE:-goaudit-e2e:ci}
FIXTURES=${GOAUDIT_PRIVILEGE_FIXTURES:-testdata/privilege-escalation}

run_fixture() {
  local fixture=$1
  local expected_verdict=$2
  local expected_reason=$3
  local output project

  output=$(mktemp)
  project=$(mktemp -d)
  trap 'rm -f "$output"; rm -rf "$project"' RETURN
  # Fixture code lives only in the test image; stage a manifest, not its tree.
  python3 - "$FIXTURES/$fixture/package.json" "$fixture" "$project" <<'PY'
import json
import pathlib
import sys

source, fixture, destination = sys.argv[1:]
name = json.loads(pathlib.Path(source).read_text())["name"]
manifest = {"name": "goaudit-e2e-project", "version": "1.0.0", "private": True,
            "dependencies": {name: f"file:/opt/goaudit-e2e/privilege-escalation/{fixture}.tgz"}}
(pathlib.Path(destination) / "package.json").write_text(json.dumps(manifest))
PY
  "$CLI" scan-project "$project" --manager=npm \
    --ci \
    --no-cache \
    --offline \
    --network=off \
    --node-image="$IMAGE" >"$output"

  python3 - "$output" "$expected_verdict" "$expected_reason" <<'PY'
import json
import sys

path, expected_verdict, expected_reason = sys.argv[1:]
with open(path, encoding="utf-8") as report_file:
    report = json.load(report_file)

observations = (
    observation
    for signal in report["signals"]
    for observation in signal["observations"]
)
reasons = {observation.get("reasonCode") for observation in observations}
if report["verdict"] != expected_verdict:
    raise SystemExit(
        f"{path}: expected verdict {expected_verdict}, got {report['verdict']}; reasons={sorted(reasons)}"
    )
if expected_reason not in reasons:
    raise SystemExit(
        f"{path}: expected reason {expected_reason}; got {sorted(reasons)}"
    )
PY
}

run_fixture sudo-id MALICIOUS PRIVILEGE_ESCALATION_EXEC
run_fixture setuid-root SUSPICIOUS PRIVILEGE_ESCALATION_ATTEMPT
run_fixture suid-copy MALICIOUS SUID_SGID_BIT_SET
