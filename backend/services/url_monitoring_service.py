"""
URL Monitoring Service - Continuous monitoring of flagged URLs.

Ported from ai-threat-detection-security-ops (Group B consolidation) and
adapted to the SIH email-forensics platform:
- Uses unified_url_check (VirusTotal / SafeBrowsing / RDAP) for re-scans
- Verdict mapping from threat_score -> Malicious / Suspicious / Safe
- Updates ThreatLog to "Resolved" when a monitored URL goes safe
- Background rescan thread starts lazily on first enrollment

Features:
- Periodic re-scanning of flagged URLs
- Status change detection and history
- Automatic threat closure when URLs become safe
- Monitoring queue management
"""

import asyncio
import logging
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

MONITOR_CONFIG = {
    "max_monitored_urls": 1000,        # Limit monitoring queue size
    "auto_close_after_safe_scans": 3,  # Close after 3 consecutive safe scans
    "escalation_threshold": 5,         # Log escalation if status flips 5+ times
    "retention_days": 30,              # Keep history for 30 days
    "scan_interval_minutes": 60,       # Default re-scan interval
}


def _verdict_from_result(result: Dict) -> tuple:
    """Map a unified_url_check result to (final_status, severity)."""
    if result.get("is_malicious"):
        return "Malicious", result.get("threat_level", "High")
    level = (result.get("threat_level") or "Low").lower()
    if level in ("critical", "high", "medium"):
        return "Suspicious", result.get("threat_level", "Medium")
    return "Safe", "Low"


def _run_in_flask_loop(coro):
    """Run an async coroutine from a sync context inside the Flask app.

    Email scan routes use `asyncio.new_event_loop().run_until_complete(...)`,
    so we follow the same pattern instead of nest_asyncio.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class URLMonitor:
    """Manages continuous monitoring of URLs for threat status changes."""

    def __init__(self):
        self.monitored_urls: Dict[str, Dict] = {}
        self.history: Dict[str, List[Dict]] = defaultdict(list)
        self._scheduler_started = False
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Queue management
    # ------------------------------------------------------------------
    def add_to_monitoring(self, url: str, initial_status: str, severity: str,
                          threat_log_id: Optional[int] = None) -> Dict:
        """Add URL to monitoring queue."""
        with self._lock:
            if len(self.monitored_urls) >= MONITOR_CONFIG["max_monitored_urls"]:
                logger.warning(
                    "Monitoring queue full (%s), cannot add %s",
                    MONITOR_CONFIG["max_monitored_urls"], url)
                return {"success": False, "error": "Monitoring queue full"}

            if url in self.monitored_urls:
                return {"success": False, "error": "Already monitored"}

            entry = {
                "url": url,
                "initial_status": initial_status,
                "current_status": initial_status,
                "severity": severity,
                "threat_log_id": threat_log_id,
                "added_at": datetime.utcnow().isoformat(),
                "last_scan": datetime.utcnow().isoformat(),
                "scan_count": 1,
                "consecutive_safe_scans": 0,
                "status_changes": 0,
                "auto_close": True,
            }
            self.monitored_urls[url] = entry
            self.history[url].append({
                "timestamp": datetime.utcnow().isoformat(),
                "status": initial_status,
                "severity": severity,
                "event": "monitoring_started",
            })

        logger.info("Added %s to monitoring queue (status: %s)", url, initial_status)
        self._ensure_scheduler()
        return {"success": True, "monitor_entry": entry}

    def remove_from_monitoring(self, url: str, reason: str = "manual_removal") -> bool:
        """Remove URL from monitoring queue."""
        with self._lock:
            if url not in self.monitored_urls:
                return False
            entry = self.monitored_urls[url]
            self.history[url].append({
                "timestamp": datetime.utcnow().isoformat(),
                "status": entry["current_status"],
                "event": "monitoring_stopped",
                "reason": reason,
            })
            del self.monitored_urls[url]
        logger.info("Removed %s from monitoring (reason: %s)", url, reason)
        return True

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------
    async def rescan_url(self, url: str) -> Dict:
        """Re-scan a monitored URL and check for status changes."""
        if url not in self.monitored_urls:
            return {"error": "URL not in monitoring queue"}

        from backend.services.threat_intelligence import unified_url_check

        entry = self.monitored_urls[url]
        previous_status = entry["current_status"]

        try:
            result = await unified_url_check(url, force_refresh=True)
            new_status, new_severity = _verdict_from_result(result)

            with self._lock:
                entry["last_scan"] = datetime.utcnow().isoformat()
                entry["scan_count"] += 1
                entry["current_status"] = new_status
                entry["severity"] = new_severity

                status_changed = previous_status != new_status
                if status_changed:
                    entry["status_changes"] += 1
                    self.history[url].append({
                        "timestamp": datetime.utcnow().isoformat(),
                        "old_status": previous_status,
                        "new_status": new_status,
                        "severity": new_severity,
                        "event": "status_changed",
                    })

                if new_status == "Safe":
                    entry["consecutive_safe_scans"] += 1
                else:
                    entry["consecutive_safe_scans"] = 0

                should_close = (
                    entry["auto_close"]
                    and entry["consecutive_safe_scans"] >= MONITOR_CONFIG["auto_close_after_safe_scans"]
                )
                if entry["status_changes"] >= MONITOR_CONFIG["escalation_threshold"]:
                    logger.warning(
                        "ESCALATION: %s has changed status %s times", url, entry["status_changes"])
                    self.history[url].append({
                        "timestamp": datetime.utcnow().isoformat(),
                        "status": new_status,
                        "event": "escalation",
                        "status_changes": entry["status_changes"],
                    })

            if status_changed:
                logger.warning("Status change for %s: %s -> %s", url, previous_status, new_status)

            if should_close:
                self.auto_close_threat(url, entry)
                return {
                    "url": url,
                    "status_changed": status_changed,
                    "previous_status": previous_status,
                    "current_status": new_status,
                    "auto_closed": True,
                    "scan_result": result,
                }

            return {
                "url": url,
                "status_changed": status_changed,
                "previous_status": previous_status,
                "current_status": new_status,
                "consecutive_safe_scans": entry["consecutive_safe_scans"],
                "auto_closed": False,
                "scan_result": result,
            }

        except Exception as e:
            logger.error("Error rescanning %s: %s", url, e)
            return {"error": str(e), "url": url}

    def auto_close_threat(self, url: str, entry: Dict):
        """Close a threat when it becomes safe; update ThreatLog and dequeue."""
        try:
            threat_log_id = entry.get("threat_log_id")
            if threat_log_id:
                from backend.models import ThreatLog, db
                within_app = False
                try:
                    from flask import has_app_context
                    within_app = has_app_context()
                except Exception:
                    pass
                if within_app:
                    threat_log = db.session.get(ThreatLog, threat_log_id)
                    if threat_log:
                        threat_log.status = "Resolved"
                        threat_log.details = (
                            f"{threat_log.details or ''}\n\n"
                            f"Auto-closed: {entry['consecutive_safe_scans']} consecutive safe scans"
                        )
                        db.session.commit()
                        logger.info("Auto-closed ThreatLog #%s for %s", threat_log_id, url)

            with self._lock:
                self.history[url].append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "status": "Safe",
                    "event": "auto_closed",
                    "consecutive_safe_scans": entry["consecutive_safe_scans"],
                })
            self.remove_from_monitoring(url, reason="auto_closed")
        except Exception as e:
            logger.error("Error auto-closing threat for %s: %s", url, e)
            try:
                from backend.models import db
                db.session.rollback()
            except Exception:
                pass

    async def scan_all_monitored(self) -> List[Dict]:
        """Scan all URLs in the monitoring queue (batched to protect API quotas)."""
        if not self.monitored_urls:
            return []

        results = []
        logger.info("Scanning %d monitored URLs", len(self.monitored_urls))
        urls = list(self.monitored_urls.keys())
        batch_size = 10

        for i in range(0, len(urls), batch_size):
            batch = urls[i:i + batch_size]
            tasks = [self.rescan_url(url) for url in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in batch_results:
                if isinstance(result, Exception):
                    logger.error("Batch scan error: %s", result)
                    continue
                results.append(result)

            if i + batch_size < len(urls):
                await asyncio.sleep(2)

        self.cleanup_old_history()
        return results

    def cleanup_old_history(self):
        """Remove history entries older than the retention period."""
        cutoff = datetime.utcnow() - timedelta(days=MONITOR_CONFIG["retention_days"])
        with self._lock:
            for url in list(self.history.keys()):
                self.history[url] = [
                    e for e in self.history[url]
                    if datetime.fromisoformat(e["timestamp"]) > cutoff
                ]
                if not self.history[url]:
                    del self.history[url]

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    def get_monitoring_stats(self) -> Dict:
        """Statistics about the current monitoring queue."""
        stats = {
            "monitored_urls_count": len(self.monitored_urls),
            "max_capacity": MONITOR_CONFIG["max_monitored_urls"],
            "capacity_used_percent": round(
                (len(self.monitored_urls) / MONITOR_CONFIG["max_monitored_urls"]) * 100, 2),
            "status_breakdown": defaultdict(int),
            "severity_breakdown": defaultdict(int),
            "avg_scan_count": 0,
            "urls_with_status_changes": 0,
            "urls_near_auto_close": 0,
            "escalated_urls": 0,
        }
        total_scans = 0
        for entry in self.monitored_urls.values():
            stats["status_breakdown"][entry["current_status"]] += 1
            stats["severity_breakdown"][entry["severity"]] += 1
            total_scans += entry["scan_count"]
            if entry["status_changes"] > 0:
                stats["urls_with_status_changes"] += 1
            if entry["consecutive_safe_scans"] >= MONITOR_CONFIG["auto_close_after_safe_scans"] - 1:
                stats["urls_near_auto_close"] += 1
            if entry["status_changes"] >= MONITOR_CONFIG["escalation_threshold"]:
                stats["escalated_urls"] += 1
        if self.monitored_urls:
            stats["avg_scan_count"] = round(total_scans / len(self.monitored_urls), 2)
        stats["status_breakdown"] = dict(stats["status_breakdown"])
        stats["severity_breakdown"] = dict(stats["severity_breakdown"])
        return stats

    def get_url_history(self, url: str) -> List[Dict]:
        """Complete history for a specific URL."""
        with self._lock:
            return list(self.history.get(url, []))

    def get_all_monitored(self) -> List[Dict]:
        """List all monitored URLs with their status."""
        with self._lock:
            return [dict(e) for e in self.monitored_urls.values()]

    # ------------------------------------------------------------------
    # Background rescan thread (lazy)
    # ------------------------------------------------------------------
    def _ensure_scheduler(self):
        if self._scheduler_started:
            return
        self._scheduler_started = True

        # Capture the Flask app so the background thread can push an app
        # context (needed for ThreatLog auto-close updates).
        try:
            from flask import current_app
            flask_app = current_app._get_current_object()
        except Exception:
            flask_app = None

        def _loop():
            interval = MONITOR_CONFIG["scan_interval_minutes"] * 60
            while True:
                time.sleep(interval)
                if not self.monitored_urls:
                    continue
                try:
                    if flask_app is not None:
                        with flask_app.app_context():
                            _run_in_flask_loop(self.scan_all_monitored())
                    else:
                        _run_in_flask_loop(self.scan_all_monitored())
                except Exception as e:
                    logger.error("Monitor scan cycle failed: %s", e)

        t = threading.Thread(target=_loop, name="url-monitor", daemon=True)
        t.start()
        logger.info("URL monitoring background thread started (every %s min)",
                    MONITOR_CONFIG["scan_interval_minutes"])


# Global monitor instance
url_monitor = URLMonitor()


def get_url_monitor() -> URLMonitor:
    """Get the global URL monitor instance."""
    return url_monitor


def add_url_to_monitor(url: str, status: str, severity: str,
                       threat_log_id: Optional[int] = None) -> Dict:
    """Add URL to monitoring queue."""
    return url_monitor.add_to_monitoring(url, status, severity, threat_log_id)


def get_monitoring_statistics() -> Dict:
    """Get monitoring queue statistics."""
    return url_monitor.get_monitoring_stats()
