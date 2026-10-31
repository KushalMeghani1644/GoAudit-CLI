#!/usr/bin/env bash
set -euo pipefail

CLI=${GOAUDIT_BIN:-./goaudit}
IMAGE=${GOAUDIT_NODE_IMAGE:-goaudit-node-sandbox:ci}
PROJECT=$(mktemp -d)
trap 'rm -rf "$PROJECT"' EXIT

# This code is inline in the manifest so no host source is needed. A second,
# intentionally failing hook below proves that lifecycle scripts actually run.
python3 - "$PROJECT" <<'PY'
import json
import pathlib
import shlex
import sys

root = pathlib.Path(sys.argv[1])
excluded = [".npmrc", "host-secret.txt", "src/index.js", "patches/host-secret.txt",
            ".yarn/host-secret.txt", "packages/child/package.json", "pnpm-workspace.yaml"]
for name in excluded:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("ignore-scripts=true\n" if name == ".npmrc" else "host-only sentinel\n")
code = (
    "const fs=require('fs');"
    "if(!fs.existsSync('/workspace/package.json'))process.exit(41);"
    f"for(const p of {json.dumps(excluded)})"
    "for(const base of ['/workspace/','/project-ro/'])"
    "if(fs.existsSync(base+p))process.exit(42);"
)
manifest = {"name": "goaudit-staging-e2e", "version": "1.0.0", "private": True,
            "scripts": {"postinstall": "node -e " + shlex.quote(code)}}
(root / "package.json").write_text(json.dumps(manifest))
PY

cp "$PROJECT/package.json" "$PROJECT/expected-manifest"
for mode in allowlist hook-control; do
  if [[ "$mode" == hook-control ]]; then
    python3 - "$PROJECT/package.json" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
manifest = json.loads(path.read_text())
manifest["scripts"]["postinstall"] = 'node -e "process.exit(42)"'
path.write_text(json.dumps(manifest))
PY
    cp "$PROJECT/package.json" "$PROJECT/expected-manifest"
  fi
  for manager in npm pnpm bun; do
    for command in scan-project scan; do
      # npm install . runs the root lifecycle hook. pnpm/bun add . have
      # different self-install hook semantics, so use scan-project for those.
      if [[ "$command" == scan && "$manager" != npm ]]; then continue; fi
      args=(scan-project "$PROJECT" "--manager=$manager")
      if [[ "$command" == scan ]]; then
        args=(scan "npm install $PROJECT")
      fi
      "$CLI" "${args[@]}" --ci --offline --network=off --no-cache \
        --node-image="$IMAGE" --bun-image="$IMAGE" >"$PROJECT/report.json"
      python3 - "$PROJECT/report.json" "$mode" "$manager" "$command" <<'PY'
import json
import sys
path, mode, manager, command = sys.argv[1:]
with open(path) as stream:
    report = json.load(stream)
meta = report.get("meta") or {}
target = (meta.get("dynamic") or {}).get("target") or {}
success = target.get("exitObserved") and target.get("exitCode", 0) == 0
expected = mode == "allowlist"
if (meta.get("sandboxRuntime") != "runsc" or not target.get("phaseObserved")
        or not target.get("exitObserved") or success != expected):
    raise SystemExit(f"{command}/{manager}/{mode}: unexpected execution\n{json.dumps(report, indent=2)}")
print(f"PASS {command}/{manager}: {mode}")
PY
      cmp "$PROJECT/package.json" "$PROJECT/expected-manifest"
      if [[ -e "$PROJECT/node_modules" ]]; then
        echo "host node_modules was modified" >&2
        exit 1
      fi
    done
  done
done
