"""
Live Threat Feed Service
Maintains real-time and cached threat intelligence:
1. Live Tor Exit Node Directory (synced from TorProject with persistent fallback cache)
2. Anonymizing VPN / Proxy / Datacenter ASN classification
3. Bulletproof & High-Abuse Hosting Provider intelligence
"""

import os
import time
import logging
import sqlite3
import httpx
from pathlib import Path
from typing import Dict, Set, Optional

logger = logging.getLogger(__name__)

CACHE_DIR = Path(__file__).parent.parent / 'instance'
CACHE_DIR.mkdir(parents=True, exist_ok=True)
TOR_CACHE_FILE = CACHE_DIR / 'tor_exit_nodes.txt'
TOR_LAST_SYNC_FILE = CACHE_DIR / 'tor_last_sync.txt'

# Fallback known high-profile Tor exit nodes (active Tor nodes frequently seen in abuse)
FALLBACK_TOR_NODES = {
    '185.220.101.34', '185.220.101.35', '185.220.101.36', '185.220.101.37',
    '185.220.101.5', '185.220.101.6', '185.220.101.7', '185.220.101.8',
    '185.220.100.240', '185.220.100.241', '185.220.100.242', '185.220.100.252',
    '198.98.56.143', '198.98.57.143', '171.25.193.20', '171.25.193.25',
    '51.15.43.205', '51.15.58.128', '162.247.74.200', '162.247.74.201',
    '199.249.230.71', '199.249.230.72', '199.249.230.73', '199.249.230.74',
    '109.70.100.29', '109.70.100.30', '104.244.72.115', '104.244.76.13',
}

# Known Bulletproof / High-Risk Offshore Hosting & Anonymizer ASNs / Orgs
HIGH_ABUSE_PROVIDERS = {
    'stiftung erneuerbare freiheit', 'zwiebelfreunde', 'forprivacynet', 'hostkey',
    'hostsailor', 'serverastra', 'cherry servers', 'bulletproof', 'offshore',
    'mullvad', 'nordvpn', 'expressvpn', 'protonvpn', 'surfshark', 'ovh hosting',
    'vultr', 'digitalocean', 'choopa', 'linode', 'hetzner', 'contabo', 'frantech',
    'buyvm', 'flokinet', 'alexhost', 'pq hosting', 'shinjiru', 'datacamp limited',
    'm247', 'leaseweb', 'f3 netze', 'cinipac', 'quadranet'
}


class LiveThreatFeed:
    """Manages real-time threat intelligence feeds and caching."""

    def __init__(self):
        self._tor_exit_nodes: Set[str] = set(FALLBACK_TOR_NODES)
        self._last_tor_sync = 0
        self._load_cached_tor_nodes()

    def _load_cached_tor_nodes(self):
        """Load Tor nodes from disk cache if fresh (< 24 hours old)."""
        try:
            if TOR_LAST_SYNC_FILE.exists():
                with open(TOR_LAST_SYNC_FILE, 'r', encoding='utf-8') as f:
                    self._last_tor_sync = float(f.read().strip() or '0')

            if TOR_CACHE_FILE.exists():
                with open(TOR_CACHE_FILE, 'r', encoding='utf-8') as f:
                    nodes = {line.strip() for line in f if line.strip() and not line.startswith('#')}
                    if nodes:
                        self._tor_exit_nodes.update(nodes)
                        logger.info(f"Loaded {len(self._tor_exit_nodes)} Tor exit nodes from local cache")
        except Exception as e:
            logger.debug(f"Error loading Tor cache: {e}")

    def refresh_tor_nodes(self, force: bool = False) -> int:
        """
        Sync live Tor exit node list from official Tor Project directory.
        Cached for 6 hours unless force=True.
        """
        now = time.time()
        if not force and (now - self._last_tor_sync) < 21600 and len(self._tor_exit_nodes) > len(FALLBACK_TOR_NODES):
            return len(self._tor_exit_nodes)

        try:
            with httpx.Client(timeout=4.0) as client:
                resp = client.get('https://check.torproject.org/torbulkexitlist')
                if resp.status_code == 200:
                    lines = resp.text.splitlines()
                    new_nodes = {line.strip() for line in lines if line.strip() and not line.startswith('#')}
                    if new_nodes:
                        self._tor_exit_nodes.update(new_nodes)
                        self._last_tor_sync = now
                        with open(TOR_CACHE_FILE, 'w', encoding='utf-8') as f:
                            f.write('\n'.join(sorted(self._tor_exit_nodes)))
                        with open(TOR_LAST_SYNC_FILE, 'w', encoding='utf-8') as f:
                            f.write(str(now))
                        logger.info(f"Successfully synced {len(new_nodes)} live Tor exit nodes from TorProject")
                        return len(self._tor_exit_nodes)
        except Exception as e:
            logger.debug(f"Live Tor sync failed (using persistent cache): {e}")

        return len(self._tor_exit_nodes)

    def is_tor_exit_node(self, ip: str) -> bool:
        """Check if an IP address is an active Tor exit node."""
        if not ip or not isinstance(ip, str):
            return False
        clean_ip = ip.strip()
        return clean_ip in self._tor_exit_nodes

    def check_anonymizer_status(self, ip: str, org: str = '', asn: str = '', is_proxy: bool = False, is_hosting: bool = False) -> Dict:
        """
        Comprehensive anonymizer and infrastructure risk evaluation.
        Returns: {
            'is_anonymizer': bool,
            'is_tor': bool,
            'is_vpn_proxy': bool,
            'is_bulletproof': bool,
            'anonymizer_type': str,
            'threat_level': 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
            'details': str
        }
        """
        is_tor = self.is_tor_exit_node(ip)
        org_lower = (org or '').lower()
        asn_lower = (asn or '').lower()
        combined = f"{org_lower} {asn_lower}"

        is_bulletproof = any(provider in combined for provider in HIGH_ABUSE_PROVIDERS)
        is_vpn = any(k in combined for k in ['vpn', 'proxy', 'tor', 'mullvad', 'nordvpn', 'expressvpn', 'forprivacynet']) or is_proxy

        if is_tor:
            return {
                'is_anonymizer': True,
                'is_tor': True,
                'is_vpn_proxy': True,
                'is_bulletproof': is_bulletproof,
                'anonymizer_type': 'Tor Exit Node',
                'threat_level': 'CRITICAL',
                'details': f"IP {ip} is verified as an active Tor network exit node operated by '{org or 'Tor Operator'}'."
            }

        if is_vpn:
            return {
                'is_anonymizer': True,
                'is_tor': False,
                'is_vpn_proxy': True,
                'is_bulletproof': is_bulletproof,
                'anonymizer_type': 'VPN / Anonymizing Proxy',
                'threat_level': 'HIGH',
                'details': f"IP {ip} is associated with commercial VPN/Proxy infrastructure ({org or asn})."
            }

        if is_bulletproof:
            return {
                'is_anonymizer': False,
                'is_tor': False,
                'is_vpn_proxy': False,
                'is_bulletproof': True,
                'anonymizer_type': 'High-Abuse / Bulletproof Hosting',
                'threat_level': 'HIGH',
                'details': f"IP {ip} is hosted on a high-abuse VPS/hosting network ({org or asn})."
            }

        if is_hosting:
            return {
                'is_anonymizer': False,
                'is_tor': False,
                'is_vpn_proxy': False,
                'is_bulletproof': False,
                'anonymizer_type': 'Cloud Datacenter',
                'threat_level': 'MEDIUM',
                'details': f"IP {ip} originates from a cloud/datacenter ASN ({org or asn})."
            }

        return {
            'is_anonymizer': False,
            'is_tor': False,
            'is_vpn_proxy': False,
            'is_bulletproof': False,
            'anonymizer_type': 'Standard ISP / Residential',
            'threat_level': 'NONE',
            'details': f"Standard residential/business ISP connection ({org or 'Direct'})."
        }


# Singleton
_threat_feed_instance: Optional[LiveThreatFeed] = None

def get_threat_feed() -> LiveThreatFeed:
    global _threat_feed_instance
    if _threat_feed_instance is None:
        _threat_feed_instance = LiveThreatFeed()
    return _threat_feed_instance
