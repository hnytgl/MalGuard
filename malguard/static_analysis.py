from __future__ import annotations

import os
import re
import struct
import subprocess
from pathlib import Path
from typing import Any

from .family_detection import detect_family_markers
from .ioc import extract_iocs
from .utils import md5_file, sha1_file, sha256_file, utc_now_iso

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UNICODE_RE = re.compile((rb"(?:[\x20-\x7e]\x00){4,}"))

SENSITIVE_API_PATTERNS = {
    "process_injection": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
    "hook_injection": ["SetWindowsHookEx", "CallNextHookEx"],
    "credential_access": ["LsaEnumerateLogonSessions", "CredEnumerate", "SamIConnect", "Mimikatz"],
    "persistence_service": ["CreateService", "StartService", "OpenSCManager"],
    "registry_persistence": ["RegSetValue", "RegCreateKey", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
    "anti_debug": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"],
    "network": ["InternetOpen", "InternetConnect", "HttpSendRequest", "WinHttpSendRequest", "connect", "send", "recv"],
    "defense_evasion": ["Add-MpPreference", "ExclusionPath", "regsvr32", "rundll32", "powershell", "FromBase64String"],
    "loader_staging": ["VirtualAlloc", "VirtualProtect", "LoadLibrary", "GetProcAddress", "CreateThread"],
}

PERSISTENCE_MARKERS = {
    "windows_run_key": [
        r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ],
    "windows_service": [r"CreateService", r"sc.exe create", r"CurrentControlSet\\Services"],
    "windows_startup_folder": [r"Startup\\", r"Start Menu\\Programs\\Startup"],
    "windows_scheduled_task": [r"schtasks", r"TaskCache\\Tree"],
    "windows_logon_script": [r"UserInitMprLogonScript"],
    "windows_appdomain_manager": [r"AppDomainManagerAssembly", r"AppDomainManagerType", r"COR_ENABLE_PROFILING"],
    "linux_cron": [r"/etc/cron", r"crontab", r"cron.d"],
    "linux_systemd": [r"/etc/systemd/system", r"systemctl enable", r".service"],
    "shell_profile": [r".bashrc", r".profile", r"/etc/profile"],
}

ACCOUNT_BACKDOOR_MARKERS = [
    "net user", "net localgroup administrators", "useradd", "adduser", "usermod -aG sudo",
    "passwd ", "sudoers", "RID-500", "administrator$",
]


def identify_format(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "PE"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data[:4] in {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"}:
        return "Mach-O"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP"
    return "unknown"


def extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    values: set[str] = set()
    for match in ASCII_RE.findall(data):
        if len(match) >= min_len:
            values.add(match.decode("latin-1", errors="ignore"))
    for match in UNICODE_RE.findall(data):
        decoded = match.decode("utf-16le", errors="ignore")
        if len(decoded) >= min_len:
            values.add(decoded)
    return sorted(values)


def detect_sensitive_sequences(strings: list[str]) -> list[dict[str, Any]]:
    joined = "\n".join(strings).lower()
    results: list[dict[str, Any]] = []
    for name, sequence in SENSITIVE_API_PATTERNS.items():
        hits = [item for item in sequence if item.lower() in joined]
        if hits:
            severity = "high" if len(hits) >= max(2, len(sequence) - 1) else "medium"
            results.append({"pattern": name, "hits": hits, "severity": severity})
    return results


def detect_persistence_markers(strings: list[str]) -> list[dict[str, Any]]:
    joined = "\n".join(strings).lower()
    findings: list[dict[str, Any]] = []
    for category, markers in PERSISTENCE_MARKERS.items():
        hits = [m for m in markers if m.lower() in joined]
        if hits:
            findings.append({"type": category, "source": "static_string", "evidence": hits})
    return findings


def detect_account_backdoors(strings: list[str]) -> list[dict[str, Any]]:
    joined = "\n".join(strings).lower()
    return [
        {"type": "account_backdoor_marker", "source": "static_string", "evidence": marker}
        for marker in ACCOUNT_BACKDOOR_MARKERS
        if marker.lower() in joined
    ]


def parse_pe(path: Path) -> dict[str, Any]:
    try:
        import pefile  # type: ignore
    except Exception as exc:
        return {"available": False, "error": f"pefile not installed: {exc}"}

    try:
        pe = pefile.PE(str(path), fast_load=False)
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="ignore")
                for imp in entry.imports:
                    imports.append({"dll": dll, "name": imp.name.decode(errors="ignore") if imp.name else None, "address": imp.address})
        exports = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exports.append({"name": sym.name.decode(errors="ignore") if sym.name else None, "address": sym.address})
        sections = [
            {
                "name": section.Name.rstrip(b"\x00").decode(errors="ignore"),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(section.get_entropy(), 3),
            }
            for section in pe.sections
        ]
        return {"available": True, "imports": imports, "exports": exports, "sections": sections}
    except Exception as exc:
        return {"available": False, "error": str(exc)}


def run_unpacker(path: Path, unpacker: str, output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = [unpacker, str(path), str(output_dir)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
    return {
        "command": cmd,
        "returncode": proc.returncode,
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
        "output_dir": str(output_dir),
    }


def analyze_static(path: Path, yara_rules: list[Path] | None = None, unpacker: str | None = None) -> dict[str, Any]:
    data = path.read_bytes()
    strings = extract_strings(data)
    file_format = identify_format(data)
    result: dict[str, Any] = {
        "schema": "malguard.static.v1",
        "generated_at": utc_now_iso(),
        "sample": {
            "path": str(path),
            "name": path.name,
            "size": path.stat().st_size,
            "format": file_format,
            "hashes": {"md5": md5_file(path), "sha1": sha1_file(path), "sha256": sha256_file(path)},
        },
        "strings": {"count": len(strings), "values": strings[:5000]},
        "iocs": extract_iocs(strings),
        "sensitive_api_sequences": detect_sensitive_sequences(strings),
        "persistence": detect_persistence_markers(strings),
        "account_backdoors": detect_account_backdoors(strings),
        "family_matches": detect_family_markers(strings),
        "yara": scan_yara(path, yara_rules or []),
        "structure": {},
    }
    if unpacker:
        result["unpacker"] = run_unpacker(path, unpacker, path.parent / f"{path.name}.unpacked")
    if file_format == "PE":
        result["structure"]["pe"] = parse_pe(path)
    elif file_format == "ELF":
        result["structure"]["elf"] = parse_elf_header(data)
    elif file_format == "Mach-O":
        result["structure"]["macho"] = {"magic": data[:4].hex()}
    return result


def parse_elf_header(data: bytes) -> dict[str, Any]:
    if len(data) < 20 or not data.startswith(b"\x7fELF"):
        return {}
    cls = {1: "32-bit", 2: "64-bit"}.get(data[4], "unknown")
    endian = "little" if data[5] == 1 else "big" if data[5] == 2 else "unknown"
    fmt = "<H" if endian == "little" else ">H"
    machine = struct.unpack(fmt, data[18:20])[0] if endian in {"little", "big"} else None
    return {"class": cls, "endianness": endian, "machine": machine}


def scan_yara(path: Path, rules: list[Path]) -> list[dict[str, Any]]:
    if not rules:
        return []
    try:
        import yara  # type: ignore
    except Exception as exc:
        return [{"error": f"yara-python not installed: {exc}"}]

    findings: list[dict[str, Any]] = []
    for rule_path in rules:
        try:
            compiled = yara.compile(filepath=str(rule_path))
            for match in compiled.match(str(path)):
                findings.append({
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": list(match.tags),
                    "meta": dict(match.meta),
                    "source": str(rule_path),
                })
        except Exception as exc:
            findings.append({"source": str(rule_path), "error": str(exc)})
    return findings
