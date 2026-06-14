from __future__ import annotations

import html
import json
import uuid
from pathlib import Path
from typing import Any

from .utils import utc_now_iso, write_json


def build_unified_report(static_report: dict[str, Any], dynamic_events: list[dict[str, Any]], correlation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "malguard.report.v1",
        "generated_at": utc_now_iso(),
        "static": static_report,
        "dynamic": {"schema": "malguard.dynamic.v1", "events": dynamic_events},
        "correlation": correlation,
    }


def write_html_report(path: Path, report: dict[str, Any]) -> None:
    sample = report.get("static", {}).get("sample", {})
    iocs = report.get("static", {}).get("iocs", {})
    timeline = report.get("correlation", {}).get("timeline", [])
    rows = []
    for ev in timeline[:500]:
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(ev.get('ts_ms', '')))}</td>"
            f"<td>{html.escape(str(ev.get('category', '')))}</td>"
            f"<td>{html.escape(str(ev.get('action', '')))}</td>"
            f"<td>{html.escape(str(ev.get('malicious_confidence', '')))}</td>"
            f"<td><code>{html.escape(json.dumps(ev.get('data', {}), ensure_ascii=False)[:800])}</code></td>"
            "</tr>"
        )
    ioc_items = []
    for kind, values in iocs.items():
        for item in values:
            ioc_items.append(f"<li><b>{html.escape(kind)}</b>: <mark>{html.escape(str(item.get('value')))}</mark></li>")

    content = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>MalGuard Report - {html.escape(str(sample.get('name', 'sample')))}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; line-height: 1.45; }}
    code {{ white-space: pre-wrap; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: .45rem; vertical-align: top; }}
    th {{ background: #f6f8fa; }}
    .card {{ border: 1px solid #ddd; border-radius: 10px; padding: 1rem; margin: 1rem 0; }}
    mark {{ background: #fff2a8; }}
  </style>
</head>
<body>
  <h1>MalGuard Malware Triage Report</h1>
  <div class="card">
    <h2>Sample</h2>
    <p><b>Name:</b> {html.escape(str(sample.get('name', '')))}<br>
    <b>Format:</b> {html.escape(str(sample.get('format', '')))}<br>
    <b>SHA256:</b> <code>{html.escape(str(sample.get('hashes', {}).get('sha256', '')))}</code></p>
  </div>
  <div class="card">
    <h2>Summary</h2>
    <pre>{html.escape(json.dumps(report.get('correlation', {}).get('summary', {}), indent=2, ensure_ascii=False))}</pre>
  </div>
  <div class="card">
    <h2>Highlighted IOCs</h2>
    <ul>{''.join(ioc_items) or '<li>No IOCs found</li>'}</ul>
  </div>
  <h2>Behavior Timeline</h2>
  <table>
    <thead><tr><th>ms</th><th>category</th><th>action</th><th>confidence</th><th>data</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</body>
</html>
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_stix(path: Path, report: dict[str, Any]) -> None:
    objects: list[dict[str, Any]] = []
    identity_id = f"identity--{uuid.uuid4()}"
    objects.append({"type": "identity", "spec_version": "2.1", "id": identity_id, "created": utc_now_iso(), "modified": utc_now_iso(), "name": "MalGuard", "identity_class": "system"})
    for kind, values in report.get("static", {}).get("iocs", {}).items():
        for item in values:
            value = item.get("value")
            if not value:
                continue
            pattern = stix_pattern(kind, str(value))
            if pattern:
                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "created": utc_now_iso(),
                    "modified": utc_now_iso(),
                    "created_by_ref": identity_id,
                    "name": f"MalGuard {kind}: {value}",
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": utc_now_iso(),
                })
    write_json(path, {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects})


def stix_pattern(kind: str, value: str) -> str | None:
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    if kind == "ips":
        return f"[ipv4-addr:value = '{escaped}']"
    if kind == "domains":
        return f"[domain-name:value = '{escaped}']"
    if kind == "urls":
        return f"[url:value = '{escaped}']"
    if kind == "emails":
        return f"[email-addr:value = '{escaped}']"
    return None

