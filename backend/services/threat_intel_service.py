"""
Threat Intelligence Service for MailForensic
Integrates real-world security intelligence feeds:
1. AbuseIPDB (IP abuse confidence score, report count, ISP reputation)
2. VirusTotal v3 (Domain & URL multi-vendor antivirus consensus)
3. ICANN RDAP (Domain registration age, Newly Registered Domain [NRD] detection)

All results are cached persistently in SQLite to ensure 0ms response on repeat queries
and protect API quotas.
"""

import os
import re
import time
import base64
import sqlite3
import logging
import httpx
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

CACHE_DB = Path(__file__).parent.parent / 'instance' / 'geo_cache.sqlite3'
CACHE_DB.parent.mkdir(parents=True, exist_ok=True)

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def _init_threat_cache():
    """Initialize SQLite tables for AbuseIPDB, VirusTotal, and RDAP caches."""
    try:
        with sqlite3.connect(CACHE_DB) as conn:
            cursor = conn.cursor()
            # AbuseIPDB cache (TTL 24 hours)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS abuseipdb_cache (
                    ip TEXT PRIMARY KEY,
                    abuse_score INTEGER,
                    total_reports INTEGER,
                    isp TEXT,
                    country_name TEXT,
                    is_whitelisted INTEGER,
                    raw_json TEXT,
                    cached_at REAL
                )
            ''')
            # VirusTotal domain/url cache (TTL 24 hours)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS virustotal_cache (
                    target_key TEXT PRIMARY KEY,
                    target_type TEXT,
                    malicious INTEGER,
                    suspicious INTEGER,
                    harmless INTEGER,
                    undetected INTEGER,
                    raw_json TEXT,
                    cached_at REAL
                )
            ''')
            # RDAP Domain Age cache (TTL 7 days)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS rdap_domain_cache (
                    domain TEXT PRIMARY KEY,
                    registration_date TEXT,
                    domain_age_days INTEGER,
                    is_nrd INTEGER,
                    maturity_tier TEXT,
                    raw_json TEXT,
                    cached_at REAL
                )
            ''')
            conn.commit()
    except Exception as e:
        logger.debug(f"Threat cache initialization error: {e}")

_init_threat_cache()


class ThreatIntelService:
    """Consolidated Threat Intelligence Client with persistent disk caching."""

    # ──────────────────────────────────────────────────────────────────────────
    # 1. AbuseIPDB
    # ──────────────────────────────────────────────────────────────────────────
    @classmethod
    def check_ip_abuse(cls, ip: str) -> Dict[str, Any]:
        """
        Check IP address against AbuseIPDB database.
        Returns: {
            'abuse_score': 0-100,
            'total_reports': int,
            'isp': str,
            'country_name': str,
            'is_known_attacker': bool,
            'source': 'abuseipdb'|'cache'|'offline'
        }
        """
        if not ip or ip in ('127.0.0.1', 'localhost', '::1', '0.0.0.0'):
            return {'abuse_score': 0, 'total_reports': 0, 'isp': 'Loopback', 'is_known_attacker': False, 'source': 'local'}

        # Check private IP ranges
        if ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.2', '172.30.', '172.31.', '192.168.')):
            return {'abuse_score': 0, 'total_reports': 0, 'isp': 'Private RFC1918 Network', 'is_known_attacker': False, 'source': 'local'}

        # 1. Check SQLite cache (24-hour TTL)
        now = time.time()
        try:
            with sqlite3.connect(CACHE_DB) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT abuse_score, total_reports, isp, country_name, is_whitelisted, cached_at FROM abuseipdb_cache WHERE ip = ?",
                    (ip,)
                )
                row = cursor.fetchone()
                if row and (now - row[5]) < 86400:
                    abuse_score = row[0]
                    return {
                        'abuse_score': abuse_score,
                        'total_reports': row[1],
                        'isp': row[2] or '',
                        'country_name': row[3] or '',
                        'is_known_attacker': abuse_score >= 40,
                        'source': 'cache'
                    }
        except Exception as e:
            logger.debug(f"AbuseIPDB cache read error: {e}")

        # 2. Query Live AbuseIPDB API
        if not ABUSEIPDB_API_KEY:
            return {'abuse_score': 0, 'total_reports': 0, 'isp': '', 'is_known_attacker': False, 'source': 'no_api_key'}

        try:
            with httpx.Client(timeout=4.0) as client:
                resp = client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                    headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    score = int(data.get("abuseConfidenceScore") or 0)
                    reports = int(data.get("totalReports") or 0)
                    isp = data.get("isp") or ""
                    country = data.get("countryName") or ""
                    whitelisted = 1 if data.get("isWhitelisted") else 0

                    # Save to cache
                    try:
                        with sqlite3.connect(CACHE_DB) as conn:
                            conn.cursor().execute(
                                """
                                INSERT OR REPLACE INTO abuseipdb_cache 
                                (ip, abuse_score, total_reports, isp, country_name, is_whitelisted, raw_json, cached_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                                (ip, score, reports, isp, country, whitelisted, resp.text, now)
                            )
                            conn.commit()
                    except Exception as ce:
                        logger.debug(f"Failed to cache AbuseIPDB data: {ce}")

                    return {
                        'abuse_score': score,
                        'total_reports': reports,
                        'isp': isp,
                        'country_name': country,
                        'is_known_attacker': score >= 40,
                        'source': 'abuseipdb_live'
                    }
        except Exception as e:
            logger.debug(f"AbuseIPDB query failed for {ip}: {e}")

        return {'abuse_score': 0, 'total_reports': 0, 'isp': '', 'is_known_attacker': False, 'source': 'offline'}

    # ──────────────────────────────────────────────────────────────────────────
    # 2. VirusTotal Domain & URL Reputation
    # ──────────────────────────────────────────────────────────────────────────
    @classmethod
    def check_virustotal_domain(cls, domain: str) -> Dict[str, Any]:
        """
        Check domain reputation against VirusTotal v3.
        Returns: { 'malicious': int, 'suspicious': int, 'harmless': int, 'is_flagged': bool }
        """
        if not domain or '.' not in domain:
            return {'malicious': 0, 'suspicious': 0, 'harmless': 0, 'is_flagged': False, 'source': 'invalid'}

        clean_domain = domain.lower().strip()
        now = time.time()

        # Cache check
        try:
            with sqlite3.connect(CACHE_DB) as conn:
                row = conn.cursor().execute(
                    "SELECT malicious, suspicious, harmless, undetected, cached_at FROM virustotal_cache WHERE target_key = ?",
                    (clean_domain,)
                ).fetchone()
                if row and (now - row[4]) < 86400:
                    mal = row[0]
                    susp = row[1]
                    return {
                        'malicious': mal,
                        'suspicious': susp,
                        'harmless': row[2],
                        'undetected': row[3],
                        'is_flagged': (mal + susp) >= 2,
                        'source': 'cache'
                    }
        except Exception as e:
            logger.debug(f"VirusTotal cache read error: {e}")

        if not VIRUSTOTAL_API_KEY:
            return {'malicious': 0, 'suspicious': 0, 'harmless': 0, 'is_flagged': False, 'source': 'no_api_key'}

        try:
            with httpx.Client(timeout=4.0) as client:
                resp = client.get(
                    f"https://www.virustotal.com/api/v3/domains/{clean_domain}",
                    headers={"x-apikey": VIRUSTOTAL_API_KEY}
                )
                if resp.status_code == 200:
                    stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    mal = stats.get("malicious", 0)
                    susp = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)

                    try:
                        with sqlite3.connect(CACHE_DB) as conn:
                            conn.cursor().execute(
                                """
                                INSERT OR REPLACE INTO virustotal_cache
                                (target_key, target_type, malicious, suspicious, harmless, undetected, raw_json, cached_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                                (clean_domain, 'domain', mal, susp, harmless, undetected, resp.text, now)
                            )
                            conn.commit()
                    except Exception as ce:
                        logger.debug(f"Failed to cache VirusTotal data: {ce}")

                    return {
                        'malicious': mal,
                        'suspicious': susp,
                        'harmless': harmless,
                        'undetected': undetected,
                        'is_flagged': (mal + susp) >= 2,
                        'source': 'virustotal_live'
                    }
        except Exception as e:
            logger.debug(f"VirusTotal query failed for domain {clean_domain}: {e}")

        return {'malicious': 0, 'suspicious': 0, 'harmless': 0, 'is_flagged': False, 'source': 'offline'}

    # ──────────────────────────────────────────────────────────────────────────
    # 3. ICANN RDAP Domain Age & Registration Protocol
    # ──────────────────────────────────────────────────────────────────────────
    @classmethod
    def check_domain_age_rdap(cls, domain: str) -> Dict[str, Any]:
        """
        Query ICANN RDAP for domain registration date.
        Calculates exact domain age in days.
        Detects Newly Registered Domains (NRDs < 30 days old) without requiring any API key.
        Returns: {
            'domain_age_days': int,
            'registration_date': str (ISO),
            'is_nrd': bool,
            'maturity_tier': 'newly_registered' | 'young' | 'established' | 'enterprise_legacy'
        }
        """
        if not domain or '.' not in domain:
            return {'domain_age_days': 9999, 'registration_date': '', 'is_nrd': False, 'maturity_tier': 'unknown'}

        # Normalize domain (extract registrable domain if subdomain exists)
        parts = domain.lower().strip().split('.')
        clean_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain.lower().strip()
        # Handle 2-part ccTLDs like .co.in, .gov.in, .co.uk
        if len(parts) >= 3 and parts[-2] in ('co', 'com', 'gov', 'edu', 'org', 'ac', 'net'):
            clean_domain = '.'.join(parts[-3:])

        now = time.time()
        # Cache check (7-day TTL)
        try:
            with sqlite3.connect(CACHE_DB) as conn:
                row = conn.cursor().execute(
                    "SELECT registration_date, domain_age_days, is_nrd, maturity_tier, cached_at FROM rdap_domain_cache WHERE domain = ?",
                    (clean_domain,)
                ).fetchone()
                if row and (now - row[4]) < (7 * 86400):
                    return {
                        'domain': clean_domain,
                        'registration_date': row[0] or '',
                        'domain_age_days': row[1],
                        'is_nrd': bool(row[2]),
                        'maturity_tier': row[3] or 'established',
                        'source': 'cache'
                    }
        except Exception as e:
            logger.debug(f"RDAP cache read error: {e}")

        # Live RDAP Bootstrap Query
        try:
            with httpx.Client(follow_redirects=True, timeout=4.0) as client:
                resp = client.get(f"https://rdap.org/domain/{clean_domain}")
                if resp.status_code == 200:
                    data = resp.json()
                    events = data.get("events", [])
                    reg_date_str = None
                    for ev in events:
                        if ev.get("eventAction") == "registration":
                            reg_date_str = ev.get("eventDate")
                            break

                    if reg_date_str:
                        # Parse ISO date
                        clean_dt_str = reg_date_str.replace('Z', '+00:00')
                        reg_dt = datetime.fromisoformat(clean_dt_str)
                        now_dt = datetime.now(timezone.utc)
                        age_days = max(0, (now_dt - reg_dt).days)

                        is_nrd = age_days < 30
                        if age_days < 30:
                            tier = 'newly_registered'
                        elif age_days < 180:
                            tier = 'young'
                        elif age_days < 1825:
                            tier = 'established'
                        else:
                            tier = 'enterprise_legacy'

                        # Cache result
                        try:
                            with sqlite3.connect(CACHE_DB) as conn:
                                conn.cursor().execute(
                                    """
                                    INSERT OR REPLACE INTO rdap_domain_cache
                                    (domain, registration_date, domain_age_days, is_nrd, maturity_tier, raw_json, cached_at)
                                    VALUES (?, ?, ?, ?, ?, ?, ?)
                                    """,
                                    (clean_domain, reg_date_str, age_days, 1 if is_nrd else 0, tier, resp.text, now)
                                )
                                conn.commit()
                        except Exception as ce:
                            logger.debug(f"Failed to cache RDAP data: {ce}")

                        return {
                            'domain': clean_domain,
                            'registration_date': reg_date_str,
                            'domain_age_days': age_days,
                            'is_nrd': is_nrd,
                            'maturity_tier': tier,
                            'source': 'rdap_live'
                        }
        except Exception as e:
            logger.debug(f"RDAP lookup failed for {clean_domain}: {e}")

        return {
            'domain': clean_domain,
            'registration_date': '',
            'domain_age_days': 1000,
            'is_nrd': False,
            'maturity_tier': 'unresolved',
            'source': 'offline'
        }


# Global singleton instance
threat_intel = ThreatIntelService()
