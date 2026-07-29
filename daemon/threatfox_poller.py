from __future__ import annotations

import logging
import os
from typing import Any, Dict

logger = logging.getLogger(__name__)


class ThreatFoxFeedPoller:
    """Pull ThreatFox indicators into the shared threat_indicators table."""

    def __init__(self) -> None:
        self.stats = {"runs": 0, "indicators_seen": 0, "inserted": 0, "updated": 0, "errors": 0}

    @staticmethod
    def is_enabled() -> bool:
        try:
            from core.config import is_integration_enabled
        except Exception:  # noqa: BLE001
            return False
        return is_integration_enabled("threatfox")

    @staticmethod
    def poll_interval_seconds() -> int:
        try:
            from core.config import get_integration_config
            cfg = get_integration_config("threatfox") or {}
            raw = cfg.get("poll_interval_seconds")
        except Exception:  # noqa: BLE001
            raw = None
        if raw is None:
            raw = os.getenv("THREATFOX_POLL_INTERVAL", "3600")
        try:
            return max(300, int(raw))
        except (TypeError, ValueError):
            return 3600

    async def run_once(self) -> Dict[str, Any]:
        if not self.is_enabled():
            logger.debug("ThreatFox integration disabled; skipping poll")
            return {"skipped": "integration_disabled"}

        try:
            from core.config import get_integration_config
            from services import threat_feed_service as feed
            from services import threatfox_feed_service as threatfox
        except Exception as e:  # noqa: BLE001
            logger.warning("ThreatFox dependencies unavailable: %s", e)
            return {"error": str(e)}

        cfg = get_integration_config("threatfox") or {}
        url = cfg.get("export_url") or threatfox.DEFAULT_EXPORT_URL
        api_key = cfg.get("api_key")

        try:
            raw = threatfox.fetch_threatfox_export(url=url, api_key=api_key)
            indicators = threatfox.parse_threatfox_export(raw)
            counts = feed.upsert_indicators(indicators)
        except Exception as e:  # noqa: BLE001
            logger.error("ThreatFox poll failed: %s", e)
            self.stats["runs"] += 1
            self.stats["errors"] += 1
            return {"source": "threatfox", "error": str(e)}

        seen = len(indicators)
        self.stats["runs"] += 1
        self.stats["indicators_seen"] += seen
        self.stats["inserted"] += counts.get("inserted", 0)
        self.stats["updated"] += counts.get("updated", 0)

        summary = {"source": "threatfox", "url": url, "seen": seen, **counts}
        if seen:
            logger.info("ThreatFox poll: %s", summary)
        return summary
