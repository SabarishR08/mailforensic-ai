"""
Unified Threat Intelligence Service
Aggregates results from VT, SafeBrowsing, PhishTank, AbuseIPDB, RDAP
"""

import os
import asyncio
import httpx
import logging
from typing import Dict, List, Optional
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

logger = logging.getLogger(__name__)


async def check_virustotal(url: str) -> Dict:
    if not VIRUSTOTAL_API_KEY:
        return {'source': 'virustotal', 'status': 'no_api_key', 'malicious_count': 0}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        async with httpx.AsyncClient(timeout=4.0) as client:
            headers = {'x-apikey': VIRUSTOTAL_API_KEY}
            resp = await client.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', headers=headers)
            if resp.status_code == 200:
                data = resp.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = data.get('malicious', 0) + data.get('suspicious', 0)
                total = sum(data.values())
                return {'source': 'virustotal', 'status': 'success', 'malicious_count': malicious, 'total_scans': total,
                        'is_malicious': malicious > 0}
            return {'source': 'virustotal', 'status': 'not_found', 'malicious_count': 0}
    except Exception as e:
        return {'source': 'virustotal', 'status': 'error', 'error': str(e), 'malicious_count': 0}


async def check_safebrowsing(url: str) -> Dict:
    if not SAFE_BROWSING_API_KEY:
        return {'source': 'safebrowsing', 'status': 'no_api_key', 'is_unsafe': False}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            payload = {
                "client": {"clientId": "ai-email-forensics", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            resp = await client.post(f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}', json=payload)
            if resp.status_code == 200:
                matches = resp.json().get('matches', [])
                return {'source': 'safebrowsing', 'status': 'success', 'is_unsafe': len(matches) > 0,
                        'threat_type': matches[0].get('threatType', '') if matches else ''}
            return {'source': 'safebrowsing', 'status': 'error', 'is_unsafe': False}
    except Exception as e:
        return {'source': 'safebrowsing', 'status': 'error', 'error': str(e), 'is_unsafe': False}


async def check_abuseipdb(ip: str) -> Dict:
    if not ABUSEIPDB_API_KEY:
        return {'source': 'abuseipdb', 'status': 'no_api_key', 'is_abusive': False}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
            resp = await client.get('https://api.abuseipdb.com/api/v2/check', headers=headers,
                                    params={'ipAddress': ip, 'maxAgeInDays': '90'})
            if resp.status_code == 200:
                data = resp.json().get('data', {})
                return {'source': 'abuseipdb', 'status': 'success',
                        'is_abusive': data.get('abuseConfidenceScore', 0) > 50,
                        'abuse_score': data.get('abuseConfidenceScore', 0),
                        'total_reports': data.get('totalReports', 0),
                        'isp': data.get('isp', ''), 'country': data.get('countryCode', ''),
                        'usage_type': data.get('usageType', '')}
            return {'source': 'abuseipdb', 'status': 'error', 'is_abusive': False}
    except Exception as e:
        return {'source': 'abuseipdb', 'status': 'error', 'error': str(e), 'is_abusive': False}


_RDAP_CACHE: Dict[str, Dict] = {}
_URL_CHECK_CACHE: Dict[str, Dict] = {}


async def check_rdap(domain: str) -> Dict:
    if not domain:
        return {'source': 'rdap', 'status': 'no_domain'}
    if domain in _RDAP_CACHE:
        return dict(_RDAP_CACHE[domain])
    try:
        rdap_headers = {
            'Accept': 'application/rdap+json, application/json',
            'User-Agent': 'MailForensic-AI/2.0 (SIH-2026; Cybersecurity-Forensics)'
        }
        async with httpx.AsyncClient(follow_redirects=True, timeout=3.5) as client:
            resp = await client.get(f'https://rdap.org/domain/{domain}', headers=rdap_headers)
            if resp.status_code == 200:
                data = resp.json()
                events = data.get('events', [])
                creation_date = None
                for event in events:
                    if event.get('eventAction') == 'registration':
                        creation_date = event.get('eventDate')
                        break
                nameservers = [ns.get('ldhName', '') for ns in data.get('nameservers', [])]
                res = {'source': 'rdap', 'status': 'success', 'domain': domain,
                       'creation_date': creation_date, 'nameservers': nameservers,
                       'status': data.get('status', [])}
                _RDAP_CACHE[domain] = res
                return dict(res)
            return {'source': 'rdap', 'status': 'error'}
    except Exception as e:
        return {'source': 'rdap', 'status': 'error', 'error': str(e)}


async def unified_url_check(url: str, force_refresh: bool = False) -> Dict:
    """Check URL across all intelligence sources concurrently with caching"""
    if not force_refresh and url in _URL_CHECK_CACHE:
        return dict(_URL_CHECK_CACHE[url])

    from urllib.parse import urlparse
    domain = urlparse(url).netloc

    tasks = [check_virustotal(url), check_safebrowsing(url), check_rdap(domain)]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    vt = results[0] if not isinstance(results[0], Exception) else {'source': 'virustotal', 'status': 'error'}
    sb = results[1] if not isinstance(results[1], Exception) else {'source': 'safebrowsing', 'status': 'error'}
    rdap = results[2] if not isinstance(results[2], Exception) else {'source': 'rdap', 'status': 'error'}

    # Calculate aggregate threat score
    threat_score = 0
    detections = []

    if vt.get('is_malicious'):
        threat_score += min(35, vt.get('malicious_count', 0) * 5)
        detections.append({'source': 'VirusTotal', 'status': 'MALICIOUS',
                          'detail': f"{vt.get('malicious_count', 0)}/{vt.get('total_scans', 0)} scanners"})

    if sb.get('is_unsafe'):
        threat_score += 30
        detections.append({'source': 'SafeBrowsing', 'status': 'UNSAFE', 'detail': sb.get('threat_type', '')})

    res = {
        'url': url,
        'threat_score': min(100, threat_score),
        'threat_level': 'Critical' if threat_score >= 70 else 'High' if threat_score >= 40 else 'Medium' if threat_score >= 20 else 'Low',
        'is_malicious': threat_score >= 30,
        'detections': detections,
        'sources': {'virustotal': vt, 'safebrowsing': sb, 'rdap': rdap},
    }
    _URL_CHECK_CACHE[url] = res
    return dict(res)
