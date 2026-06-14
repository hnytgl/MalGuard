from __future__ import annotations

from typing import Any


def _ioc_values(static_report: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for rows in static_report.get("iocs", {}).values():
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict) and row.get("value"):
                    values.add(str(row["value"]).lower())
    return values


def _network_values(dynamic_events: list[dict[str, Any]]) -> set[str]:
    values: set[str] = set()
    for ev in dynamic_events:
        if ev.get("category") != "network":
            continue
        data = ev.get("data", {})
        for key in ("dst_ip", "destination_ip", "remote_ip", "host", "domain", "url", "dst_host"):
            if key in data and data[key]:
                values.add(str(data[key]).lower())
    return values


def _dynamic_persistence(dynamic_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    markers = []
    for ev in dynamic_events:
        text = f"{ev.get('action')} {ev.get('data')}".lower()
        if any(token in text for token in ("runonce", "\\run", "createservice", "schtasks", "systemctl enable", "cron", ".bashrc", "startup")):
            markers.append({"type": "dynamic_persistence", "source": ev.get("source"), "event": ev})
    return markers


def confidence_for_event(ev: dict[str, Any]) -> float:
    text = f"{ev.get('category')} {ev.get('action')} {ev.get('data')}".lower()
    score = 0.15
    for token, weight in {
        "remote thread": 0.4,
        "writeremote": 0.35,
        "createremotethread": 0.45,
        "runonce": 0.3,
        "\\run": 0.25,
        "createservice": 0.35,
        "administrator": 0.35,
        "useradd": 0.35,
        "connect": 0.15,
        "http": 0.1,
        "isdebuggerpresent": 0.2,
    }.items():
        if token in text:
            score += weight
    return min(round(score, 2), 1.0)


def correlate(static_report: dict[str, Any], dynamic_events: list[dict[str, Any]]) -> dict[str, Any]:
    static_iocs = _ioc_values(static_report)
    dynamic_network = _network_values(dynamic_events)
    c2_matches = sorted(static_iocs & dynamic_network)
    static_persistence = static_report.get("persistence", [])
    dynamic_persistence = _dynamic_persistence(dynamic_events)
    timeline = [
        {**ev, "malicious_confidence": confidence_for_event(ev)}
        for ev in sorted(dynamic_events, key=lambda item: item.get("ts_ms", 0))
    ]
    return {
        "schema": "malguard.correlation.v1",
        "sample": static_report.get("sample", {}),
        "c2_matches": [{"value": value, "source": "static_and_dynamic"} for value in c2_matches],
        "persistence": dedupe_persistence(static_persistence + dynamic_persistence),
        "timeline": timeline,
        "summary": {
            "static_ioc_count": len(static_iocs),
            "dynamic_event_count": len(dynamic_events),
            "c2_match_count": len(c2_matches),
            "high_confidence_event_count": sum(1 for ev in timeline if ev["malicious_confidence"] >= 0.7),
        },
    }


def dedupe_persistence(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for row in rows:
        key = (row.get("type"), str(row.get("evidence") or row.get("event")))
        if key not in seen:
            seen.add(key)
            result.append(row)
    return result

