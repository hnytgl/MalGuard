from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FamilyRule:
    family: str
    description: str
    indicators: tuple[str, ...]
    weight: float = 1.0


SILVER_FOX_RULES: tuple[FamilyRule, ...] = (
    FamilyRule(
        family="SilverFox",
        description="Fake installer or staged payload artifacts",
        indicators=(
            "insttect.exe",
            "microsoft.dll",
            "monitor.bat",
            "updated.ps1",
            "target.pid",
            "config.ini",
            "config2.ini",
            "single.ini",
            "policymanagement.xml",
        ),
        weight=1.2,
    ),
    FamilyRule(
        family="SilverFox",
        description=".NET task and GAC/AppDomainManager persistence markers",
        indicators=(
            ".net framework ngen vtie",
            "appdomainmanagerassembly",
            "appdomainmanagertype",
            "\\assembly\\gac_msil\\",
            "cor_enable_profiling",
            "cor_profiler_path",
        ),
        weight=1.4,
    ),
    FamilyRule(
        family="SilverFox",
        description="Command-line persistence and defense exclusion behavior",
        indicators=(
            "add-mppreference",
            "exclusionpath",
            "regsvr32",
            "schtasks",
            "/create",
            "runonce",
            "userinitmprlogonscript",
            "pendingfilerenameoperations",
        ),
        weight=1.0,
    ),
    FamilyRule(
        family="SilverFox",
        description="ActiveX/Internet Zone security weakening",
        indicators=(
            "\\internet settings\\zones\\0",
            "\\internet settings\\zones\\1",
            "\\internet settings\\zones\\2",
            "\\internet settings\\zones\\3",
            "\\internet settings\\zones\\4",
            "1201",
            "1001",
            "1004",
        ),
        weight=0.9,
    ),
    FamilyRule(
        family="SilverFox",
        description="Observed SilverFox/Winos/ValleyRAT payload naming and exports",
        indicators=(
            "win7.log",
            "winos",
            "valleyrat",
            "hackbrian",
            "vfpower",
            "zhuxianlu",
            "vuqnwmsabvwqh",
            "vjancavesu223f",
        ),
        weight=1.5,
    ),
    FamilyRule(
        family="SilverFox",
        description="Common SilverFox C2 ports in public reports",
        indicators=("8852", "9090", "9091", "9092", "18852", "18853"),
        weight=0.8,
    ),
)


def detect_family_markers(strings: list[str]) -> list[dict[str, Any]]:
    text = "\n".join(strings).lower()
    findings: list[dict[str, Any]] = []

    for rule in SILVER_FOX_RULES:
        hits = [indicator for indicator in rule.indicators if indicator in text]
        if not hits:
            continue
        confidence = min(1.0, round((len(hits) / len(rule.indicators)) * rule.weight, 2))
        findings.append(
            {
                "family": rule.family,
                "description": rule.description,
                "source": "static_string",
                "evidence": hits,
                "confidence": confidence,
            }
        )

    return sorted(findings, key=lambda row: row["confidence"], reverse=True)

