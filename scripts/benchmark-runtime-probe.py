#!/usr/bin/env python3
"""Benchmark real scans; retain reports and reject incomplete/failed samples."""

import argparse
import atexit
import json
import statistics
import subprocess
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", default="./goaudit")
    parser.add_argument("--image", required=True, help="Use the same pinned image for every run")
    parser.add_argument("--output", type=Path, required=True, help="New directory for reports and cache")
    parser.add_argument("--samples", type=int, default=3, help="Samples per mode and cache path")
    args = parser.parse_args()
    if args.samples < 2:
        parser.error("at least two samples are needed")
    args.output.mkdir(parents=True, exist_ok=False)
    cli = str(Path(args.cli).resolve())
    cache_dir = str(args.output.resolve() / "cache")
    # Only this newly created benchmark cache is cleaned, never the user's
    # normal cache. Preserve reports while releasing its idle warm container.
    def cleanup_cache():
        result = subprocess.run([cli, "cache", "clean", "--cache-dir", cache_dir],
                                capture_output=True, text=True)
        (args.output / "cache-cleanup.log").write_text(result.stdout + result.stderr)
    atexit.register(cleanup_cache)
    command = "npm install lodash@4.17.21 yaml@2.8.1 minimist@1.2.8 marked@15.0.12"
    common = ["--ci", "--network=on", "--node-image", args.image, "--timeout=120s",
              "--probe-timeout=30s", "--fail-on=malicious,inconclusive",
              "--cache-dir", cache_dir]
    records = []
    for cache_path in ("fresh", "cached"):
        for sample in range(args.samples):
            # Reverse pair order to reduce systematic warm-up/order bias.
            for enabled in ([False, True] if sample % 2 == 0 else [True, False]):
                name = f"{cache_path}-{sample + 1}-{'probe' if enabled else 'default'}"
                if cache_path == "cached":
                    # Preparation is outside timing; scans still include GoAudit's
                    # normal replacement-cache preparation after consuming a cache.
                    warm = subprocess.run([cli, "scan", command, *common, "--warm-cache"],
                                          capture_output=True, text=True)
                    (args.output / f"{name}.warm.log").write_text(warm.stdout + warm.stderr)
                    if warm.returncode:
                        raise RuntimeError(f"cache preparation failed: {name}")
                flags = ["--no-cache"] if cache_path == "fresh" else []
                if enabled:
                    flags.append("--runtime-probe")
                argv = [cli, "scan", command, *common, *flags]
                start = time.monotonic()
                result = subprocess.run(argv, capture_output=True, text=True)
                elapsed = time.monotonic() - start
                (args.output / f"{name}.json").write_text(result.stdout)
                (args.output / f"{name}.stderr").write_text(result.stderr)
                if result.returncode:
                    raise RuntimeError(f"failed/inconclusive sample: {name}: {result.stderr}")
                report = json.loads(result.stdout)
                if report["verdict"] != "CLEAN":
                    raise RuntimeError(f"unexpected verdict: {name}: {report['verdict']}")
                meta = report["meta"]
                if meta["sandboxRuntime"] != "runsc":
                    raise RuntimeError("benchmark must use gVisor")
                for phase in ("target", "probe") if enabled else ("target",):
                    health = meta["dynamic"][phase]
                    if not all(health.get(key) for key in
                               ("expected", "phaseObserved", "exitObserved", "syscallObserved")):
                        raise RuntimeError(f"missing {phase} evidence: {name}")
                    if health.get("exitCode", 0) != 0 or health.get("timedOut"):
                        raise RuntimeError(f"incomplete {phase}: {name}")
                if not enabled and meta["dynamic"]["probe"].get("phaseObserved"):
                    raise RuntimeError(f"default unexpectedly executed probe: {name}")
                diagnostics = report.get("diagnostics", [])
                if enabled:
                    exercised = {d.get("path") for d in diagnostics if d["reasonCode"] == "PROBE_API_OK"}
                    required = {"lodash:chunk", "yaml:parse", "minimist:minimist", "marked:parse"}
                    if not required <= exercised:
                        raise RuntimeError(f"missing API exercises: {name}: {required - exercised}")
                codes = sorted(o["reasonCode"] for signal in report["signals"] for o in signal["observations"])
                record = dict(name=name, cache=cache_path, probe=enabled, seconds=round(elapsed, 3),
                              verdict=report["verdict"], signalCodes=codes,
                              diagnosticCodes=sorted(d["reasonCode"] for d in diagnostics))
                records.append(record)
                (args.output / "samples.json").write_text(json.dumps(records, indent=2) + "\n")
                print(json.dumps(record), flush=True)
    summary = dict(command=command, image=args.image, samplesPerMode=args.samples,
                   timing="Whole CLI wall time; cached runs include automatic replacement-cache preparation",
                   groups=[])
    for cache_path in ("fresh", "cached"):
        for enabled in (False, True):
            times = [r["seconds"] for r in records if r["cache"] == cache_path and r["probe"] == enabled]
            summary["groups"].append(dict(cache=cache_path, probe=enabled, seconds=times,
                                          mean=round(statistics.mean(times), 3),
                                          median=round(statistics.median(times), 3)))
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
