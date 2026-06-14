from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlparse

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"\bhttps?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+\b", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"\b(?=.{4,253}\b)(?!\d+\.\d+\.\d+\.\d+\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\b"
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")

COMMON_TLDS = {
    "com", "net", "org", "info", "biz", "cn", "ru", "io", "co", "uk", "de",
    "jp", "xyz", "top", "site", "online", "cc", "me", "us", "tv",
}


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    size = len(value)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def dga_score(domain: str) -> float:
    labels = domain.lower().strip(".").split(".")
    sld = labels[-2] if len(labels) >= 2 else labels[0]
    if not sld:
        return 0.0
    vowels = sum(1 for c in sld if c in "aeiou")
    digits = sum(1 for c in sld if c.isdigit())
    hyphens = sld.count("-")
    score = 0.0
    if len(sld) >= 12:
        score += 0.2
    if entropy(sld) >= 3.3:
        score += 0.3
    if vowels / max(len(sld), 1) < 0.18:
        score += 0.2
    if digits / max(len(sld), 1) > 0.25:
        score += 0.2
    if hyphens >= 2:
        score += 0.1
    if labels[-1] not in COMMON_TLDS:
        score += 0.1
    return min(score, 1.0)


def extract_iocs(strings: list[str]) -> dict[str, list[dict[str, object]]]:
    text = "\n".join(strings)
    ips = sorted(set(IP_RE.findall(text)))
    urls = sorted(set(URL_RE.findall(text)))
    domains = set(DOMAIN_RE.findall(text))
    emails = sorted(set(EMAIL_RE.findall(text)))

    for url in urls:
        host = urlparse(url).hostname
        if host:
            domains.add(host)
    domains = {d.lower().strip(".") for d in domains if not IP_RE.fullmatch(d)}

    return {
        "ips": [{"value": ip, "type": "ipv4"} for ip in ips],
        "domains": [
            {"value": d, "type": "domain", "dga_score": round(dga_score(d), 3), "dga_suspected": dga_score(d) >= 0.65}
            for d in sorted(domains)
        ],
        "urls": [{"value": u, "type": "url"} for u in urls],
        "emails": [{"value": e, "type": "email"} for e in emails],
    }

