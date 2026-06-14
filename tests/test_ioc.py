from malguard.ioc import dga_score, extract_iocs


def test_extract_iocs_and_dga_score():
    values = [
        "http://203.0.113.10/a",
        "callback.example.com",
        "xj4kq9zptm2v.net",
    ]
    iocs = extract_iocs(values)
    assert {"value": "203.0.113.10", "type": "ipv4"} in iocs["ips"]
    assert any(item["value"] == "callback.example.com" for item in iocs["domains"])
    assert dga_score("xj4kq9zptm2v.net") > 0.4

