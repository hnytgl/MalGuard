from pathlib import Path

from malguard.correlate import correlate
from malguard.static_analysis import analyze_static


def test_static_and_correlation(tmp_path: Path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(
        b"MZ CreateRemoteThread WriteProcessMemory http://203.0.113.10/a "
        b"Software\\Microsoft\\Windows\\CurrentVersion\\Run net localgroup administrators"
    )
    static = analyze_static(sample)
    dynamic = [
        {
            "ts_ms": 1,
            "category": "network",
            "action": "connect",
            "data": {"dst_ip": "203.0.113.10", "dst_port": 443},
            "source": "test",
        }
    ]
    corr = correlate(static, dynamic)
    assert corr["summary"]["c2_match_count"] == 1
    assert static["sensitive_api_sequences"]
    assert static["account_backdoors"]


def test_silverfox_family_markers_are_reported(tmp_path: Path):
    sample = tmp_path / "silverfox_like.bin"
    sample.write_bytes(
        b"MZ Add-MpPreference ExclusionPath C:\\ insttect.exe Microsoft.dll "
        b"regsvr32 Config.ini VFPower .NET Framework NGEN vTie "
        b"http://120.89.71.226:18852/a"
    )

    static = analyze_static(sample)

    assert any(item["family"] == "SilverFox" for item in static["family_matches"])
    assert any("insttect.exe" in item["evidence"] for item in static["family_matches"])
    assert static["sensitive_api_sequences"]
