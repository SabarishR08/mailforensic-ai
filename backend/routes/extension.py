"""
Browser extension API routes.

Ported from ai-threat-detection-security-ops (Group B consolidation) and
adapted to the SIH email-forensics platform:
- POST /check-url          → deep scan a URL (VirusTotal/SafeBrowsing/RDAP),
                             log to ThreatLog, auto-enroll threats in monitoring
- GET  /api/recent_threats → recent ThreatLog entries for extension cache sync
- POST /api/tab-activity   → lightweight tab telemetry from the extension
- GET  /api/monitoring/stats → URL monitoring queue statistics
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request

from backend.models import ThreatLog, db
from backend.services.threat_intelligence import unified_url_check
from backend.services.url_monitoring_service import (
    add_url_to_monitor,
    get_url_monitor,
)

logger = logging.getLogger(__name__)

extension_bp = Blueprint("extension", __name__)

_BLOCKING_STATUSES = ("Malicious", "Phishing", "Suspicious")


def _verdict(result: dict) -> tuple:
    """Map unified_url_check result to (final_status, severity, detected_by)."""
    if result.get("is_malicious"):
        sources = [d.get("source") for d in result.get("detections", [])]
        return (
            "Malicious",
            result.get("threat_level", "High"),
            f"ThreatIntel ({', '.join(sources) or 'pipeline'})",
        )
    level = (result.get("threat_level") or "Low").lower()
    if level in ("critical", "high", "medium"):
        return "Suspicious", result.get("threat_level", "Medium"), "ThreatIntel (heuristic)"
    return "Safe", "Low", "ThreatIntel (no detections)"


def _run_async(coro):
    """Run a coroutine from sync Flask context (same pattern as email routes)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@extension_bp.route("/check-url", methods=["POST"])
def check_url():
    """
    URL scanning endpoint for the browser extension.
    Deterministic verdict from threat intel; logs to ThreatLog and
    auto-enrolls detected threats into the monitoring queue.
    """
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    force_refresh = bool(data.get("force_refresh", False))

    if not url:
        return jsonify({"error": "URL is required"}), 400
    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "Only http/https URLs can be scanned"}), 400

    try:
        result = _run_async(unified_url_check(url, force_refresh=force_refresh))
        status, severity, detected_by = _verdict(result)

        # Defensive: prefer a recent deterministic Phishing/Malicious verdict
        # for the same domain over an intermittent 'Safe' (source timeout).
        try:
            from urllib.parse import urlparse
            host = urlparse(url).netloc or url
            window = datetime.utcnow() - timedelta(minutes=10)
            recent = (
                ThreatLog.query
                .filter(ThreatLog.timestamp >= window)
                .filter(ThreatLog.url.contains(host))
                .order_by(ThreatLog.timestamp.desc())
                .limit(10)
                .all()
            )
            for r in recent:
                if (r.status or "").lower() in ("phishing", "malicious"):
                    status = r.status
                    severity = r.severity or severity
                    detected_by = r.flagged_reason or detected_by
                    break
        except Exception:
            pass

        entry = ThreatLog(
            category="url_scan",
            url=url,
            flagged_reason=f"{detected_by} ({status})",
            severity=severity,
            status=status,
            risk_score=result.get("threat_score", 0),
            details=json.dumps({
                "sources": result.get("sources", {}),
                "detections": result.get("detections", []),
                "origin": "browser_extension",
            }),
        )
        db.session.add(entry)
        db.session.commit()

        # Auto-enroll detected threats in continuous monitoring
        if status in _BLOCKING_STATUSES:
            try:
                monitor_result = add_url_to_monitor(
                    url=url,
                    status=status,
                    severity=severity,
                    threat_log_id=entry.id,
                )
                if monitor_result.get("success"):
                    logger.info("Auto-enrolled %s in monitoring queue", url)
            except Exception as monitor_err:
                logger.error("Monitoring enrollment error: %s", monitor_err)

        return jsonify({
            "url": url,
            "status": status,
            "severity": severity,
            "detected_by": detected_by,
            "threat_score": result.get("threat_score", 0),
            "detections": result.get("detections", []),
            "monitored": status in _BLOCKING_STATUSES,
        })

    except Exception as e:
        logger.error("Error during check-url for %s: %s", url, e)
        db.session.rollback()
        return jsonify({"error": "Error during threat lookup"}), 500


@extension_bp.route("/api/recent_threats", methods=["GET"])
def recent_threats():
    """
    Recent ThreatLog entries for syncing with clients (browser extension).
    Query params: limit (default 20).
    """
    try:
        limit = min(int(request.args.get("limit", 20)), 200)
        logs = (
            ThreatLog.query
            .filter_by(category="url_scan")
            .order_by(ThreatLog.timestamp.desc())
            .limit(limit)
            .all()
        )
        out = []
        for l in logs:
            try:
                details = json.loads(l.details) if l.details else None
            except Exception:
                details = None
            out.append({
                "id": l.id,
                "timestamp": l.timestamp.isoformat() if l.timestamp else None,
                "url": l.url,
                "status": l.status,
                "severity": l.severity,
                "flagged_reason": l.flagged_reason,
                "details": details,
            })
        return jsonify({"results": out})
    except Exception as e:
        logger.error("Error fetching recent threats: %s", e)
        return jsonify({"error": "Error fetching recent threats"}), 500


@extension_bp.route("/api/tab-activity", methods=["POST"])
def tab_activity():
    """Tab activity ingestion from the browser extension."""
    try:
        data = request.get_json(silent=True) or {}
        url = (data.get("url") or "").strip()
        title = data.get("title") or ""
        action = data.get("action") or "switch"

        if not url:
            return jsonify({"error": "url required"}), 400

        entry = ThreatLog(
            category="tabs",
            url=url,
            status="INFO",
            severity="Low",
            flagged_reason=f"Tab {action}: {title}".strip(),
        )
        db.session.add(entry)
        db.session.commit()
        return jsonify({"ok": True})
    except Exception as e:
        logger.error("tab_activity error: %s", e)
        db.session.rollback()
        return jsonify({"error": "failed"}), 500


@extension_bp.route("/api/monitoring/stats", methods=["GET"])
def monitoring_stats():
    """Monitoring queue statistics (for the dashboard later, if wanted)."""
    try:
        monitor = get_url_monitor()
        return jsonify({
            "stats": monitor.get_monitoring_stats(),
            "monitored": monitor.get_all_monitored(),
        })
    except Exception as e:
        logger.error("monitoring_stats error: %s", e)
        return jsonify({"error": "failed"}), 500
