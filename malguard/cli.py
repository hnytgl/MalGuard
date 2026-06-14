from __future__ import annotations

import argparse
from pathlib import Path

from .correlate import correlate
from .dynamic import normalize_events, sandbox_run
from .report import build_unified_report, write_html_report, write_stix
from .static_analysis import analyze_static
from .utils import read_json, read_jsonl, write_json, write_jsonl


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="malguard", description="Defensive malware triage toolkit")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_static = sub.add_parser("static", help="Run static analysis and emit JSON")
    p_static.add_argument("sample", type=Path)
    p_static.add_argument("-o", "--output", type=Path, required=True)
    p_static.add_argument("--yara", type=Path, action="append", default=[])
    p_static.add_argument("--unpacker")

    p_norm = sub.add_parser("dynamic-normalize", help="Normalize sandbox logs to JSON Lines")
    p_norm.add_argument("inputs", type=Path, nargs="+")
    p_norm.add_argument("-o", "--output", type=Path, required=True)

    p_corr = sub.add_parser("correlate", help="Correlate static JSON and dynamic JSONL")
    p_corr.add_argument("--static", type=Path, required=True)
    p_corr.add_argument("--dynamic", type=Path, required=True)
    p_corr.add_argument("-o", "--output", type=Path, required=True)

    p_report = sub.add_parser("report", help="Build unified JSON, HTML, and STIX reports")
    p_report.add_argument("--static", type=Path, required=True)
    p_report.add_argument("--dynamic", type=Path, required=True)
    p_report.add_argument("--correlation", type=Path, required=True)
    p_report.add_argument("--json", type=Path, required=True)
    p_report.add_argument("--html", type=Path, required=True)
    p_report.add_argument("--stix", type=Path, required=True)

    p_run = sub.add_parser("sandbox-run", help="Execute a sample only inside an isolated sandbox VM")
    p_run.add_argument("sample", type=Path)
    p_run.add_argument("-o", "--output", type=Path, required=True)
    p_run.add_argument("--timeout", type=int, default=120)
    p_run.add_argument("--arg", action="append", default=[])
    p_run.add_argument("--i-understand-risk", action="store_true")

    args = parser.parse_args(argv)
    if args.cmd == "static":
        write_json(args.output, analyze_static(args.sample, args.yara, args.unpacker))
    elif args.cmd == "dynamic-normalize":
        write_jsonl(args.output, normalize_events(args.inputs))
    elif args.cmd == "correlate":
        write_json(args.output, correlate(read_json(args.static), read_jsonl(args.dynamic)))
    elif args.cmd == "report":
        report = build_unified_report(read_json(args.static), read_jsonl(args.dynamic), read_json(args.correlation))
        write_json(args.json, report)
        write_html_report(args.html, report)
        write_stix(args.stix, report)
    elif args.cmd == "sandbox-run":
        summary = sandbox_run(args.sample, args.output, args.timeout, args.arg, args.i_understand_risk)
        write_json(args.output.with_suffix(args.output.suffix + ".summary.json"), summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

