#!/usr/bin/env bash
set -euo pipefail

criterion_dir="${1:-target/criterion}"
baseline_file="${2:-scripts/bench-baseline.json}"
tolerance="${3:-0.20}"

python3 - "$criterion_dir" "$baseline_file" "$tolerance" <<'PY'
import json
import math
import sys
from pathlib import Path

criterion_dir = Path(sys.argv[1])
baseline_file = Path(sys.argv[2])
tolerance = float(sys.argv[3])

if not criterion_dir.exists():
    print(f"criterion directory not found: {criterion_dir}", file=sys.stderr)
    sys.exit(1)

baseline = {}
if baseline_file.exists():
    baseline = json.loads(baseline_file.read_text(encoding="utf-8"))

sample_files = sorted(criterion_dir.rglob("sample.json"))
if not sample_files:
    print(f"no Criterion sample data found under {criterion_dir}", file=sys.stderr)
    sys.exit(1)

rows = []
regressions = []

for sample_path in sample_files:
    benchmark_dir = sample_path.parent.parent
    benchmark_name = benchmark_dir.relative_to(criterion_dir).as_posix()

    payload = json.loads(sample_path.read_text(encoding="utf-8"))
    iterations = payload.get("iters", [])
    times = payload.get("times", [])

    if not iterations or not times or len(iterations) != len(times):
        continue

    per_iteration_us = [
        (float(total_time_ns) / float(iter_count)) / 1000.0
        for iter_count, total_time_ns in zip(iterations, times)
        if iter_count
    ]
    if not per_iteration_us:
        continue

    per_iteration_us.sort()
    percentile_index = max(0, math.ceil(len(per_iteration_us) * 0.99) - 1)
    p99_us = per_iteration_us[percentile_index]

    baseline_us = baseline.get(benchmark_name)
    delta_pct = None
    status = "INFO"

    if baseline_us is not None:
        delta_pct = ((p99_us - baseline_us) / baseline_us) * 100.0
        if p99_us > baseline_us * (1.0 + tolerance):
            status = "FAIL"
            regressions.append((benchmark_name, p99_us, baseline_us, delta_pct))
        else:
            status = "OK"

    rows.append((benchmark_name, p99_us, baseline_us, delta_pct, status))

if not rows:
    print(f"no usable Criterion sample data found under {criterion_dir}", file=sys.stderr)
    sys.exit(1)

name_width = max(len("benchmark"), max(len(row[0]) for row in rows))
header = (
    f"{'benchmark'.ljust(name_width)}  "
    f"{'p99_us':>12}  "
    f"{'baseline_us':>12}  "
    f"{'delta':>9}  "
    f"{'status':>6}"
)
print(header)
print("-" * len(header))

for benchmark_name, p99_us, baseline_us, delta_pct, status in rows:
    baseline_text = f"{baseline_us:.2f}" if baseline_us is not None else "-"
    delta_text = f"{delta_pct:+.1f}%" if delta_pct is not None else "-"
    print(
        f"{benchmark_name.ljust(name_width)}  "
        f"{p99_us:12.2f}  "
        f"{baseline_text:>12}  "
        f"{delta_text:>9}  "
        f"{status:>6}"
    )

if regressions:
    print("", file=sys.stderr)
    print("performance regressions detected:", file=sys.stderr)
    for benchmark_name, p99_us, baseline_us, delta_pct in regressions:
        print(
            f"  {benchmark_name}: p99={p99_us:.2f}us baseline={baseline_us:.2f}us delta={delta_pct:+.1f}%",
            file=sys.stderr,
        )
    sys.exit(2)
PY
