"""
Compile-time overhead of the TrustLex pipeline.

Generates synthetic, valid programs of 10 to 5,000 top-level statements
(a mix of var, input, sanitize, interpolation and blocks), runs every stage
with main.run_pipeline, and reports the median of 5 runs per stage. The
one-time LALR table construction is excluded (it is reported separately as
setup time).

    python eval/latency.py [--sizes 10 50 ...] [--runs 5] [--out DIR]

Writes eval/results/latency.csv, latency.json and latency.png.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import metadata, results_dir  # noqa: E402

from main import run_pipeline  # noqa: E402
from semantic import SecurityPolicy  # noqa: E402

SIZES = (10, 50, 100, 500, 1000, 2000, 5000)
STAGES = ("Lexical analysis", "Syntax analysis", "Security analysis", "Code generation", "Optimization -O1")


def generate_program(statements: int) -> str:
    """A valid program with exactly `statements` top-level statements.

    Variables only reference a small pool of base values, so templates stay
    small and the cost measured is the pipeline's, not quadratic string growth.
    """
    lines = [
        "input user_msg",
        "input doc from rag",
        'input lang : enum("en", "fr")',
        'var persona = "You are a helpful assistant."',
        "var safe_msg = sanitize(user_msg)",
    ]
    i = 0
    while len(lines) < statements:
        kind = i % 8
        if kind == 0:
            lines.append(f"input in{i}")
        elif kind == 1:
            lines.append(f'var t{i} = "Rule {i}: be concise. {{persona}}"')
        elif kind == 2:
            lines.append(f"var s{i} = sanitize(in{i - 2} + doc)")
        elif kind == 3:
            lines.append(f'var c{i} = "Note " + safe_msg + " in {{lang}}"')
        elif kind == 4:
            lines.append(f's{i - 2} = "Reset {i}: " + s{i - 2}')
        elif kind == 5:
            lines.append(f'system {{ "Section {i}." insert(t{i - 4}) insert(s{i - 3}) "{{c{i - 2}}}" }}')
        elif kind == 6:
            lines.append(f"instruction {{ insert(in{i - 6}) insert(doc) }}")
        else:
            lines.append(f'var u{i} = "{{t{i - 6}}} / {{c{i - 4}}}"')
        i += 1
    # References only point backwards, so truncating keeps the program valid.
    lines = lines[:statements - 1] + ['instruction { "Answer the user." insert(user_msg) }']
    return "\n".join(lines) + "\n"


def measure(sizes=SIZES, runs: int = 5) -> list[dict]:
    rows = []
    for n in sizes:
        source = generate_program(n)
        samples = {stage: [] for stage in STAGES}
        setup = []
        for _ in range(runs):
            result = run_pipeline(source, f"bench_{n}.tlx", SecurityPolicy.strict(), level=1)
            if result.compiled is None:
                raise RuntimeError(f"generated program of size {n} does not compile:\n"
                                   + result.checked.diagnostics.render())
            setup.append(result.setup_ms)
            for stage in result.stages:
                samples[stage.name].append(stage.ms)
        medians = {stage: statistics.median(v) for stage, v in samples.items()}
        rows.append({
            "statements": n, "lines": source.count("\n"), "bytes": len(source.encode("utf-8")),
            **{f"{stage} ms": round(ms, 4) for stage, ms in medians.items()},
            "total ms": round(sum(medians.values()), 4),
            "setup ms (first run)": round(setup[0], 3),
        })
    return rows


def plot(rows: list[dict], path: Path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    xs = [r["statements"] for r in rows]
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.plot(xs, [r["total ms"] for r in rows], marker="o", linewidth=2.5, color="black", label="total")
    for stage in STAGES:
        ax.plot(xs, [max(r[f"{stage} ms"], 1e-4) for r in rows], marker=".", linewidth=1.2, label=stage)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("program size (top-level statements)")
    ax.set_ylabel("compile time (ms, median of runs)")
    ax.set_title("TrustLex compile-time overhead by stage")
    ax.grid(True, which="both", alpha=0.3)
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure TrustLex compile time per stage.")
    parser.add_argument("--sizes", type=int, nargs="+", default=list(SIZES))
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--out", type=Path, help="output directory (default: eval/results)")
    parser.add_argument("--no-plot", action="store_true")
    args = parser.parse_args(argv)
    out = results_dir(args.out)

    rows = measure(args.sizes, args.runs)
    with (out / "latency.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (out / "latency.json").write_text(json.dumps(
        {"metadata": metadata(script="eval/latency.py", runs=args.runs), "rows": rows}, indent=2), encoding="utf-8")
    if not args.no_plot:
        plot(rows, out / "latency.png")

    print(f"{'statements':>10} {'total ms':>10} " + " ".join(f"{s.split()[0][:8]:>9}" for s in STAGES))
    for r in rows:
        print(f"{r['statements']:>10} {r['total ms']:>10.2f} " + " ".join(f"{r[f'{s} ms']:>9.2f}" for s in STAGES))
    print(f"wrote {out / 'latency.csv'}" + ("" if args.no_plot else " and latency.png"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
