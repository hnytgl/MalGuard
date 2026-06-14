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

