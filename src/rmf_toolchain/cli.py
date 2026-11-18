"""Command-line interface.

    rmf-toolchain run --inputs inputs --out out [--as-of 2026-11-17] [--schema-dir schemas]

Exit codes: 0 = every step ran and every OSCAL output is schema-valid,
1 = a step failed or an output is invalid, 2 = bad arguments.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path

from rmf_toolchain import __version__
from rmf_toolchain.pipeline import Pipeline, StepFailed
from rmf_toolchain.report import summary_dict, summary_markdown, validate_outputs

DEFAULT_AS_OF = date(2026, 11, 17)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rmf-toolchain", description="Run the sample system through every RMF step.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run", help="run the whole pipeline")
    r.add_argument("--inputs", default="inputs", help="input folder (default: inputs)")
    r.add_argument("--out", default="out", help="output folder; replaced on every run (default: out)")
    r.add_argument(
        "--as-of",
        type=date.fromisoformat,
        default=DEFAULT_AS_OF,
        help=f"date due dates are judged against (default {DEFAULT_AS_OF}, so runs are repeatable)",
    )
    r.add_argument("--schema-dir", help="validate every OSCAL output against the NIST schemas in this folder")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    pipeline = Pipeline(Path(args.inputs), Path(args.out), args.as_of)
    failed = None
    try:
        pipeline.run()
    except StepFailed as exc:
        failed = str(exc)
    validation = validate_outputs(Path(args.out), Path(args.schema_dir)) if args.schema_dir and not failed else None
    md = summary_markdown(pipeline, validation)
    (Path(args.out) / "README.md").write_text(md, encoding="utf-8")
    (Path(args.out) / "summary.json").write_text(
        json.dumps(summary_dict(pipeline, validation), indent=2) + "\n", encoding="utf-8"
    )
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(md)
    for r in pipeline.results:
        print(f"{'ok ' if r.ok else 'FAIL'} {r.number}. {r.rmf_step:<30} {r.headline}")
    if failed:
        print(f"error: {failed}", file=sys.stderr)
        return 1
    if validation is not None:
        bad = [v for v in validation if not v["valid"]]
        print(f"OSCAL: {len(validation) - len(bad)}/{len(validation)} documents valid against NIST 1.1.2 schemas")
        if bad:
            for v in bad:
                print(f"  invalid: {v['file']}: {v['errors'][0]}", file=sys.stderr)
            return 1
    print(f"summary: {Path(args.out) / 'README.md'}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
