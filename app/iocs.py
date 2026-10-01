import re
from typing import Any

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|gov|edu|local|xyz|info)\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")


def extract_iocs(text: str) -> dict[str, list[str]]:
    urls = sorted(set(URL_RE.findall(text)))
    ips = sorted(set(IPV4_RE.findall(text)))
    hashes = sorted(set(HASH_RE.findall(text)))
    domains = sorted({item.lower() for item in DOMAIN_RE.findall(text)})
    domain_from_urls = []
    for url in urls:
        host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0].split(":")[0]
        if host:
            domain_from_urls.append(host.lower())
    domains = sorted(set(domains).union(domain_from_urls))
    return {
        "ip_addresses": ips,
        "domains": domains,
        "urls": urls,
        "hashes": hashes,
    }


def extract_from_evidence(evidence: dict[str, Any] | list[Any]) -> dict[str, list[str]]:
    return extract_iocs(str(evidence))
