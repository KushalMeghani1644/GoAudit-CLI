#!/usr/bin/env bash
set -euo pipefail

CLI=${GOAUDIT_BIN:-./goaudit}
IMAGE=${GOAUDIT_NODE_IMAGE:-goaudit-node-sandbox:ci}
FIXTURES=${GOAUDIT_PRIVILEGE_FIXTURES:-testdata/privilege-escalation}

run_fixture() {
  local fixture=$1
  local expected_verdict=$2
  local expected_reason=$3
  local output

  output=$(mktemp)
  trap 'rm -f "$output"' RETURN
  "$CLI" scan "env NPM_CONFIG_USERCONFIG=/dev/null npm install ./$FIXTURES/$fixture" \
    --ci \
    --skip-probe \
    --no-cache \
    --network=off \
    --node-image="$IMAGE" >"$output"

  python3 - "$output" "$expected_verdict" "$expected_reason" <<'PY'
import json
import sys

path, expected_verdict, expected_reason = sys.argv[1:]
with open(path, encoding="utf-8") as report_file:
    report = json.load(report_file)

reasons = {finding.get("reasonCode") for finding in report["findings"]}
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
