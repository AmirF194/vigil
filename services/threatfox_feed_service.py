from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from services.threat_feed_service import (
    NormalizedIndicator,
    _confidence_to_level,
    _parse_dt,
)

logger = logging.getLogger(__name__)

DEFAULT_EXPORT_URL = "https://threatfox.abuse.ch/export/json/recent/"

# Map ThreatFox ioc_type values to our normalized indicator_type.
_THREATFOX_TO_VIGIL_TYPE: Dict[str, str] = {
    "ip:port": "ip",
    "domain": "domain",
    "url": "url",
    "md5_hash": "hash_md5",
    "sha1_hash": "hash_sha1",
    "sha256_hash": "hash_sha256",
}


def fetch_threatfox_export(
    url: str = DEFAULT_EXPORT_URL, api_key: str | None = None, timeout: int = 60
) -> Dict[str, Any]:
    import requests

    headers = {"Accept": "application/json"}
    if api_key:
        headers["Auth-Key"] = api_key
    resp = requests.get(url, headers=headers, timeout=timeout)
    resp.raise_for_status()
    content = resp.content
    if content[:2] == b"PK":  # zip magic — the full dump ships as full.json.zip
        import io
        import zipfile

        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            content = zf.read(zf.namelist()[0])
    return json.loads(content)


def parse_threatfox_export(
    raw: Dict[str, Any], source: str = "threatfox"
) -> List[NormalizedIndicator]:
    out: List[NormalizedIndicator] = []
    for entries in raw.values():
        for entry in entries if isinstance(entries, list) else [entries]:
            ind = _parse_entry(entry, source)
            if ind is not None:
                out.append(ind)
    return out


def _parse_entry(entry: Dict[str, Any], source: str) -> NormalizedIndicator | None:
    vigil_type = _THREATFOX_TO_VIGIL_TYPE.get(entry.get("ioc_type", ""))
    value = (entry.get("ioc_value") or "").strip()
    if not vigil_type or not value:
        return None
    if vigil_type == "ip":
        value = _extract_ip(value)  # findings carry bare IPs, ThreatFox stores ip:port

    confidence = entry.get("confidence_level")
    confidence = float(confidence) if confidence is not None else None
    return NormalizedIndicator(
        indicator_type=vigil_type,
        indicator_value=value,
        source=source,
        collection_id=None,
        confidence=confidence,
        threat_level=_confidence_to_level(confidence),
        labels=_build_labels(entry),
        valid_from=_parse_dt(entry.get("first_seen_utc")),
        valid_until=None,
        raw_stix=entry,
    )


def _extract_ip(value: str) -> str:
    if value.startswith("["):  # [ipv6]:port
        return value[1:].partition("]")[0]
    if value.count(":") == 1:  # ipv4:port
        return value.split(":", 1)[0]
    return value


def _build_labels(entry: Dict[str, Any]) -> List[str]:
    candidates: List[str] = []
    tags = entry.get("tags")
    if isinstance(tags, str):
        candidates.extend(t.strip() for t in tags.split(","))
    elif isinstance(tags, list):
        candidates.extend(str(t).strip() for t in tags)
    candidates.extend(
        str(entry.get(k)).strip()
        for k in ("malware_printable", "malware", "threat_type")
        if entry.get(k)
    )
    seen: Dict[str, None] = {}
    for c in candidates:
        if c and c not in seen:
            seen[c] = None
    return list(seen)
