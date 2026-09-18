"""
ThreatLog sync bridge (Group B consolidation).

Email scans persist to EmailScanResult, but the browser extension's cache-sync
feed (/api/recent_threats) reads ThreatLog. This module mirrors URLs flagged
during email scans into ThreatLog (category=url_scan) and enrolls detected
threats in the continuous monitoring queue, so a URL that arrived in a
phishing email is blocked the moment a user clicks it — even before any
live deep scan completes.
"""

import json
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

_BLOCKING_STATUSES = ("Malicious", "Phishing", "Suspicious")


def _classify_url(unified: Dict = None, url_intel: Dict = None) -> tuple:
    """
    Derive (status, severity) for a URL from available analysis results.
    Prefers the unified threat-intel verdict; falls back to URLAnalyzer risk.
    """
    if unified:
        score = unified.get("threat_score", 0)
        if unified.get("is_malicious") or score >= 30:
            return "Malicious", unified.get("threat_level", "High")
        level = (unified.get("threat_level") or "Low").lower()
        if level in ("critical", "high", "medium") or score >= 20:
            return "Suspicious", unified.get("threat_level", "Medium")

    if url_intel:
        risk = url_intel.get("risk_score", 0) or 0
        if risk >= 70:
            return "Malicious", "High"
        if risk >= 40:
            return "Suspicious", "Medium"

    return None, None  # nothing worth logging


def sync_scan_result_to_threatlog(result: Dict) -> List[int]:
    """
    Mirror flagged URLs from one email-scan result into ThreatLog and the
    monitoring queue. Returns the list of created ThreatLog ids.

    Safe to call for every scanned email: URLs without a negative verdict
    are skipped, and monitoring enrollment deduplicates.
    """
    created_ids: List[int] = []
    try:
        # Import inside the function so this module stays import-safe
        # in contexts without an app/db (e.g. training scripts).
        from backend.models import ThreatLog, db
        from backend.services.url_monitoring_service import add_url_to_monitor

        urls_found: List[str] = result.get("urls_found") or []
        if not urls_found:
            return created_ids

        url_results: Dict = result.get("url_results") or {}
        url_intel_details: Dict = (result.get("url_intelligence") or {}).get("details") or {}
        ml_prediction = (result.get("ml") or {}).get("prediction", "unknown")
        email_id = result.get("email_id", "")

        for url in urls_found[:10]:
            unified = url_results.get(url)
            intel = url_intel_details.get(url)
            status, severity = _classify_url(unified, intel)
            if not status:
                continue

            detections = (unified or {}).get("detections", [])
            entry = ThreatLog(
                category="url_scan",
                url=url,
                status=status,
                severity=severity,
                flagged_reason=f"Email forensics scan ({ml_prediction})",
                details=json.dumps({
                    "email_id": email_id,
                    "origin": "email_scan",
                    "detections": detections,
                    "url_intel_risk": (intel or {}).get("risk_score"),
                }),
            )
            db.session.add(entry)
            try:
                db.session.commit()
                created_ids.append(entry.id)
            except Exception:
                db.session.rollback()
                continue

            if status in _BLOCKING_STATUSES:
                try:
                    add_url_to_monitor(
                        url=url, status=status, severity=severity,
                        threat_log_id=entry.id,
                    )
                except Exception as monitor_err:
                    logger.error("Monitoring enrollment error for %s: %s", url, monitor_err)

        if created_ids:
            logger.info("Mirrored %d flagged URL(s) from email %s to ThreatLog",
                        len(created_ids), email_id)

    except Exception as e:
        logger.error("threat_log_sync error: %s", e)

    return created_ids
