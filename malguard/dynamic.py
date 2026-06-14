from __future__ import annotations

import csv
import json
import platform
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable

from .utils import sha256_file, utc_now_iso, write_jsonl


def event(ts_ms: int, category: str, action: str, data: dict[str, Any], source: str) -> dict[str, Any]:
    return {"ts_ms": ts_ms, "category": category, "action": action, "data": data, "source": source}


def normalize_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                raw = json.loads(line)
                rows.append({
                    "ts_ms": int(raw.get("ts_ms", raw.get("timestamp_ms", 0))),
                    "category": raw.get("category", "unknown"),
                    "action": raw.get("action", raw.get("event", "unknown")),
                    "data": raw.get("data", raw),
                    "source": raw.get("source", str(path)),
                })
    return rows


def normalize_procmon_csv(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader):
            operation = row.get("Operation", "unknown")
            path_value = row.get("Path", "")
            category = "registry" if operation.startswith("Reg") else "file" if path_value else "process"
            rows.append(event(idx, category, operation, row, "procmon_csv"))
    return rows


def normalize_strace(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    interesting = {
        "open": "file", "openat": "file", "creat": "file", "unlink": "file", "rename": "file",
        "connect": "network", "sendto": "network", "recvfrom": "network",
        "execve": "process", "clone": "process", "fork": "process",
    }
    for idx, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines()):
        call = line.split("(", 1)[0].strip()
        if call in interesting:
            rows.append(event(idx, interesting[call], call, {"raw": line[:2000]}, "strace"))
    return rows


def normalize_events(inputs: Iterable[Path]) -> list[dict[str, Any]]:
    all_events: list[dict[str, Any]] = []
    for path in inputs:
        suffix = path.suffix.lower()
        if suffix == ".jsonl":
            all_events.extend(normalize_jsonl(path))
        elif suffix == ".csv":
            all_events.extend(normalize_procmon_csv(path))
        else:
            all_events.extend(normalize_strace(path))
    return sorted(all_events, key=lambda item: item.get("ts_ms", 0))


def sandbox_run(sample: Path, output: Path, timeout: int = 120, args: list[str] | None = None, acknowledge_risk: bool = False) -> dict[str, Any]:
    if not acknowledge_risk:
        raise RuntimeError("Refusing to execute sample without --i-understand-risk. Use only inside an isolated VM/sandbox.")
    start = time.time()
    before_hash = sha256_file(sample)
    cmd = [str(sample), *(args or [])]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    elapsed_ms = int((time.time() - start) * 1000)
    events = [
        event(0, "process", "start", {"command": cmd, "platform": platform.platform(), "sample_sha256": before_hash}, "sandbox_runner"),
        event(elapsed_ms, "process", "exit", {"returncode": proc.returncode, "stdout_tail": proc.stdout[-2048:], "stderr_tail": proc.stderr[-2048:]}, "sandbox_runner"),
    ]
    write_jsonl(output, events)
    return {"output": str(output), "events": len(events), "returncode": proc.returncode, "elapsed_ms": elapsed_ms}

