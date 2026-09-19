"""General API routes + Threat Intelligence analytics"""
import json
import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request
from sqlalchemy import func
from backend.models import ThreatLog, EmailScanResult, db

logger = logging.getLogger(__name__)
api_bp = Blueprint('api', __name__)


@api_bp.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'ai-email-forensics'})


@api_bp.route('/stats')
def stats():
    return jsonify({
        'total_scans': EmailScanResult.query.count(),
        'phishing_detected': EmailScanResult.query.filter_by(ml_prediction='phishing').count(),
        'total_threats': ThreatLog.query.filter(ThreatLog.severity.in_(['High', 'Critical'])).count(),
    })


@api_bp.route('/geo/threats')
def geo_threats():
    """Return all scans with geo data for map visualization"""
    scans = EmailScanResult.query.filter(EmailScanResult.geo_country.isnot(None)).all()
    points = []
    for s in scans:
        result = json.loads(s.full_result) if s.full_result else {}
        geo = result.get('geo', {})
        lat = geo.get('latitude')
        lon = geo.get('longitude')
        if lat is not None and lon is not None and lat != 0.0 and lon != 0.0:
            points.append({
                'lat': lat,
                'lon': lon,
                'country': geo.get('country', ''),
                'city': geo.get('city', ''),
                'risk_score': s.risk_score or 0,
                'risk_level': s.risk_level or 'Unknown',
                'email_id': s.email_id,
                'is_tor': geo.get('anonymizer', {}).get('is_tor', False),
                'anonymizer_type': geo.get('anonymizer', {}).get('anonymizer_type', ''),
                'timestamp': s.timestamp.isoformat() if s.timestamp else '',
            })
    return jsonify({'points': points, 'count': len(points)})


@api_bp.route('/geo/lookup', methods=['GET', 'POST'])
def api_geo_lookup():
    """
    On-demand real-time deep investigation endpoint for any IP, domain, or host.
    Used for live audience/judge tests during SIH presentations.
    """
    target = ''
    if request.method == 'POST':
        target = request.json.get('target', '') if request.is_json else request.form.get('target', '')
    else:
        target = request.args.get('target', '')

    target = (target or '').strip()
    if not target:
        return jsonify({'error': 'No target IP or domain provided'}), 400

    from backend.services.geo_service import get_geo_service
    geo_service = get_geo_service()

    if target.startswith('http://') or target.startswith('https://'):
        geo_result = geo_service.geolocate_url_target(target)
    elif any(c.isalpha() for c in target) and '.' in target:
        geo_result = geo_service.lookup_domain(target)
    else:
        geo_result = geo_service.lookup_ip(target)

    return jsonify({
        'status': 'success',
        'target': target,
        'result': geo_result
    })


# ---------------------------------------------------------------------------
# Threat Intelligence Analytics API
# ---------------------------------------------------------------------------

@api_bp.route('/threat-intel/summary')
def threat_intel_summary():
    """Overview stats for the threat intel dashboard"""
    total = EmailScanResult.query.count()
    phishing = EmailScanResult.query.filter_by(ml_prediction='phishing').count()
    legitimate = EmailScanResult.query.filter_by(ml_prediction='legitimate').count()
    avg_risk = db.session.query(func.avg(EmailScanResult.risk_score)).scalar() or 0
    avg_trust = db.session.query(func.avg(EmailScanResult.forensic_trust_score)).scalar() or 0

    # Severity breakdown
    risk_levels = db.session.query(
        EmailScanResult.risk_level, func.count(EmailScanResult.id)
    ).group_by(EmailScanResult.risk_level).all()

    # Unique geo origins
    countries = db.session.query(
        EmailScanResult.geo_country, func.count(EmailScanResult.id)
    ).filter(
        EmailScanResult.geo_country.isnot(None),
        EmailScanResult.geo_country != ''
    ).group_by(EmailScanResult.geo_country).count()  # number of distinct countries

    return jsonify({
        'total_scans': total,
        'phishing_count': phishing,
        'legitimate_count': legitimate,
        'phishing_rate': round(phishing / total * 100, 1) if total > 0 else 0,
        'avg_risk_score': round(float(avg_risk), 1),
        'avg_trust_score': round(float(avg_trust), 1),
        'risk_levels': {level: count for level, count in risk_levels if level},
        'unique_countries': countries,
    })


@api_bp.route('/threat-intel/trends')
def threat_intel_trends():
    """Phishing vs legitimate counts per day for the last N days"""
    days = request.args.get('days', 30, type=int)
    cutoff = datetime.utcnow() - timedelta(days=days)

    rows = db.session.query(
        func.date(EmailScanResult.timestamp).label('day'),
        EmailScanResult.ml_prediction,
        func.count(EmailScanResult.id)
    ).filter(
        EmailScanResult.timestamp >= cutoff
    ).group_by('day', EmailScanResult.ml_prediction).all()

    # Build a dict: { 'YYYY-MM-DD': { 'phishing': N, 'legitimate': N } }
    trends = defaultdict(lambda: {'phishing': 0, 'legitimate': 0, 'unknown': 0})
    for day, prediction, count in rows:
        day_str = day.isoformat() if hasattr(day, 'isoformat') else str(day or 'unknown')
        pred = prediction or 'unknown'
        if pred in ('phishing', 'legitimate', 'unknown'):
            trends[day_str][pred] = count

    # Fill in missing days with zeros
    labels = []
    phishing_data = []
    legitimate_data = []
    today = datetime.utcnow().date()
    for i in range(days, -1, -1):
        d = (today - timedelta(days=i)).isoformat()
        labels.append(d)
        phishing_data.append(trends[d]['phishing'])
        legitimate_data.append(trends[d]['legitimate'])

    return jsonify({
        'labels': labels,
        'phishing': phishing_data,
        'legitimate': legitimate_data,
        'days': days,
    })


@api_bp.route('/threat-intel/distribution')
def threat_intel_distribution():
    """Risk level + ML prediction distribution"""
    # Risk level distribution
    risk_dist = db.session.query(
        EmailScanResult.risk_level, func.count(EmailScanResult.id)
    ).group_by(EmailScanResult.risk_level).all()

    # ML prediction distribution
    ml_dist = db.session.query(
        EmailScanResult.ml_prediction, func.count(EmailScanResult.id)
    ).group_by(EmailScanResult.ml_prediction).all()

    # Risk score histogram (buckets of 10)
    all_scores = db.session.query(EmailScanResult.risk_score).filter(
        EmailScanResult.risk_score.isnot(None)
    ).all()
    score_buckets = [0] * 10  # 0-10, 10-20, ..., 90-100
    for (score,) in all_scores:
        bucket = min(score // 10, 9)
        score_buckets[bucket] += 1

    return jsonify({
        'risk_levels': {level: count for level, count in risk_dist if level},
        'ml_predictions': {pred: count for pred, count in ml_dist if pred},
        'risk_histogram': {
            'labels': ['0-10', '10-20', '20-30', '30-40', '40-50', '50-60', '60-70', '70-80', '80-90', '90-100'],
            'values': score_buckets,
        },
    })


@api_bp.route('/threat-intel/top-sources')
def threat_intel_top_sources():
    """Top countries and ASNs sending threats"""
    # Top countries by scan count
    countries = db.session.query(
        EmailScanResult.geo_country, func.count(EmailScanResult.id)
    ).filter(
        EmailScanResult.geo_country.isnot(None),
        EmailScanResult.geo_country != ''
    ).group_by(EmailScanResult.geo_country).order_by(
        func.count(EmailScanResult.id).desc()
    ).limit(15).all()

    # Top countries by average risk score
    country_risk = db.session.query(
        EmailScanResult.geo_country, func.avg(EmailScanResult.risk_score)
    ).filter(
        EmailScanResult.geo_country.isnot(None),
        EmailScanResult.geo_country != ''
    ).group_by(EmailScanResult.geo_country).order_by(
        func.avg(EmailScanResult.risk_score).desc()
    ).limit(15).all()

    # Phishing rate per country (top 10 by volume)
    country_phishing = db.session.query(
        EmailScanResult.geo_country,
        func.count(EmailScanResult.id),
        func.sum(func.cast(EmailScanResult.ml_prediction == 'phishing', db.Integer))
    ).filter(
        EmailScanResult.geo_country.isnot(None),
        EmailScanResult.geo_country != ''
    ).group_by(EmailScanResult.geo_country).order_by(
        func.count(EmailScanResult.id).desc()
    ).limit(10).all()

    return jsonify({
        'by_volume': [{'country': c, 'count': n} for c, n in countries if c],
        'by_risk': [{'country': c, 'avg_risk': round(float(r), 1)} for c, r in country_risk if c],
        'phishing_rate': [
            {'country': c, 'total': int(t), 'phishing': int(p or 0),
             'rate': round(int(p or 0) / int(t) * 100, 1) if int(t) > 0 else 0}
            for c, t, p in country_phishing if c
        ],
    })


@api_bp.route('/threat-intel/auth-trends')
def threat_intel_auth_trends():
    """SPF/DKIM/DMARC failure rates over time"""
    days = request.args.get('days', 30, type=int)
    cutoff = datetime.utcnow() - timedelta(days=days)

    scans = EmailScanResult.query.filter(
        EmailScanResult.timestamp >= cutoff
    ).order_by(EmailScanResult.timestamp.asc()).all()

    # Aggregate auth failures per day
    auth_by_day = defaultdict(lambda: {'spf_fail': 0, 'dkim_fail': 0, 'dmarc_fail': 0, 'total': 0})
    for scan in scans:
        if not scan.full_result:
            continue
        try:
            result = json.loads(scan.full_result)
            auth = result.get('forensic', {}).get('authentication', {})
            day = scan.timestamp.date().isoformat() if scan.timestamp else 'unknown'
            auth_by_day[day]['total'] += 1
            if auth.get('spf') != 'PASS':
                auth_by_day[day]['spf_fail'] += 1
            if auth.get('dkim') != 'PASS':
                auth_by_day[day]['dkim_fail'] += 1
            if auth.get('dmarc') != 'PASS':
                auth_by_day[day]['dmarc_fail'] += 1
        except Exception:
            continue

    labels = []
    spf_rates = []
    dkim_rates = []
    dmarc_rates = []
    today = datetime.utcnow().date()
    for i in range(days, -1, -1):
        d = (today - timedelta(days=i)).isoformat()
        labels.append(d)
        day_data = auth_by_day[d]
        total = day_data['total'] or 1
        spf_rates.append(round(day_data['spf_fail'] / total * 100, 1))
        dkim_rates.append(round(day_data['dkim_fail'] / total * 100, 1))
        dmarc_rates.append(round(day_data['dmarc_fail'] / total * 100, 1))

    return jsonify({
        'labels': labels,
        'spf_failure_rate': spf_rates,
        'dkim_failure_rate': dkim_rates,
        'dmarc_failure_rate': dmarc_rates,
    })


@api_bp.route('/threat-intel/recent')
def threat_intel_recent():
    """Recent scan results for the activity feed"""
    limit = request.args.get('limit', 25, type=int)
    scans = EmailScanResult.query.order_by(
        EmailScanResult.timestamp.desc()
    ).limit(limit).all()

    results = []
    for s in scans:
        entry = s.to_dict()
        # Enrich with forensic summary from JSON blob
        if s.full_result:
            try:
                full = json.loads(s.full_result)
                entry['from'] = full.get('from', '')
                entry['subject'] = full.get('subject', '')
                entry['geo_city'] = full.get('geo', {}).get('city', '')
                entry['auth_all_pass'] = full.get('forensic', {}).get('authentication', {}).get('all_pass', False)
            except Exception:
                pass
        results.append(entry)

    return jsonify({'scans': results, 'count': len(results)})


# ---------------------------------------------------------------------------
# Threat Map API
# ---------------------------------------------------------------------------

@api_bp.route('/threat-map/points')
def threat_map_points():
    """
    Return geo-tagged threat data for map visualization.
    Query params: days (int), risk_level (str), threat_type (str)
    """
    days = request.args.get('days', 30, type=int)
    risk_filter = request.args.get('risk_level', '')
    threat_filter = request.args.get('threat_type', '')

    since = datetime.utcnow() - timedelta(days=days)
    query = EmailScanResult.query.filter(EmailScanResult.timestamp >= since)

    if risk_filter:
        query = query.filter(EmailScanResult.risk_level == risk_filter)
    if threat_filter == 'phishing':
        query = query.filter(EmailScanResult.ml_prediction == 'phishing')
    elif threat_filter == 'legitimate':
        query = query.filter(EmailScanResult.ml_prediction == 'legitimate')

    scans = query.all()
    points = []
    for s in scans:
        if not s.full_result:
            continue
        try:
            full = json.loads(s.full_result)
        except Exception:
            continue

        geo = full.get('geo', {})
        forensic = full.get('forensic', {})
        routing = forensic.get('routing', {})

        # Main sender origin point — use is not None to handle 0.0 coords
        lat = geo.get('latitude')
        lon = geo.get('longitude')
        if lat is not None and lon is not None and lat != 0.0 and lon != 0.0:
            points.append({
                'lat': lat,
                'lon': lon,
                'type': 'origin',
                'country': geo.get('country', ''),
                'country_code': geo.get('country_code', ''),
                'city': geo.get('city', ''),
                'asn': geo.get('asn', ''),
                'org': geo.get('org', ''),
                'hosting': geo.get('is_hosting', False),
                'risk_score': s.risk_score or 0,
                'risk_level': s.risk_level or 'Unknown',
                'prediction': s.ml_prediction or 'unknown',
                'email_id': s.email_id or '',
                'from': full.get('from', ''),
                'subject': full.get('subject', ''),
                'timestamp': s.timestamp.isoformat() if s.timestamp else '',
                'auth': forensic.get('authentication', {}),
                'trust_score': forensic.get('trust_score', 0),
                'anonymizer': geo.get('anonymizer', {}),
                'temporal_analysis': forensic.get('temporal_analysis', {}),
            })

        # Routing hop points (for polyline trail)
        hops = routing.get('hops', [])
        hop_points = []
        for hop in hops:
            hlat = hop.get('geo', {}).get('latitude')
            hlon = hop.get('geo', {}).get('longitude')
            if hlat is not None and hlon is not None and hlat != 0.0 and hlon != 0.0:
                hop_points.append({
                    'lat': hlat,
                    'lon': hlon,
                    'ip': hop.get('ip', ''),
                    'country': hop['geo'].get('country', ''),
                    'suspicious': hop.get('suspicious', False),
                })
        if hop_points:
            points.append({
                'type': 'route',
                'hops': hop_points,
                'email_id': s.email_id or '',
                'risk_level': s.risk_level or 'Unknown',
            })

        # Dual-Vector Payload Infrastructure Points & Cross-Border Correlation Vectors
        geo_corr = full.get('geo_correlation', {})
        if geo_corr.get('correlated'):
            for t in geo_corr.get('targets', []):
                tlat = t.get('latitude')
                tlon = t.get('longitude')
                if tlat and tlon and tlat != 0.0 and tlon != 0.0:
                    points.append({
                        'lat': tlat,
                        'lon': tlon,
                        'type': 'payload_infra',
                        'country': t.get('country', ''),
                        'country_code': t.get('country_code', ''),
                        'city': t.get('city', ''),
                        'asn': t.get('asn', ''),
                        'org': t.get('org', ''),
                        'hostname': t.get('hostname', ''),
                        'target_url': t.get('url', ''),
                        'distance_km': t.get('distance_km', 0),
                        'risk_score': 90 if t.get('anonymizer', {}).get('is_tor') else 75,
                        'risk_level': 'Critical' if t.get('anonymizer', {}).get('is_tor') else 'High',
                        'prediction': 'phishing',
                        'email_id': s.email_id or '',
                        'anonymizer': t.get('anonymizer', {}),
                    })
                    # Add correlation vector if origin coordinates exist
                    if lat and lon and lat != 0.0 and lon != 0.0:
                        points.append({
                            'type': 'correlation_vector',
                            'email_id': s.email_id or '',
                            'origin': {'lat': lat, 'lon': lon, 'city': geo.get('city', ''), 'country': geo.get('country', '')},
                            'target': {'lat': tlat, 'lon': tlon, 'city': t.get('city', ''), 'country': t.get('country', '')},
                            'distance_km': t.get('distance_km', 0),
                            'cross_border': t.get('cross_border', False),
                        })

    return jsonify({'points': points, 'count': len(points)})


@api_bp.route('/threat-map/backfill', methods=['POST'])
def threat_map_backfill():
    """Re-geolocate scans that have bad/missing geo data"""
    from backend.services.geo_service import get_geo_service
    
    geo_service = get_geo_service()
    # Find scans with XX geo or missing lat/lon
    scans = EmailScanResult.query.filter(
        (EmailScanResult.geo_country == 'XX') | (EmailScanResult.geo_country == '') | (EmailScanResult.geo_country.is_(None))
    ).all()
    
    updated = 0
    for s in scans:
        if not s.origin_ip or s.origin_ip.startswith('10.') or s.origin_ip.startswith('192.168.'):
            continue  # Skip private IPs
        try:
            geo_data = geo_service.lookup_ip(s.origin_ip)
            if geo_data and geo_data.get('country_code') != 'XX':
                s.geo_country = geo_data.get('country_code', 'XX')
                # Update the full_result JSON with new geo data
                if s.full_result:
                    full = json.loads(s.full_result)
                    full['geo'] = geo_data
                    s.full_result = json.dumps(full, default=str)
                updated += 1
        except Exception as e:
            logger.debug(f"Backfill failed for {s.email_id}: {e}")
    
    db.session.commit()
    return jsonify({'updated': updated, 'total_checked': len(scans)})


@api_bp.route('/threat-map/stats')
def threat_map_stats():
    """
    Aggregated stats for the threat map sidebar.
    Returns country breakdown, top threats, risk distribution.
    """
    days = request.args.get('days', 30, type=int)
    since = datetime.utcnow() - timedelta(days=days)
    scans = EmailScanResult.query.filter(
        EmailScanResult.timestamp >= since
    ).all()

    country_stats = defaultdict(lambda: {'count': 0, 'phishing': 0, 'total_risk': 0})
    risk_dist = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Safe': 0}
    total = 0
    geo_count = 0

    for s in scans:
        total += 1
        risk_level = s.risk_level or 'Unknown'
        if risk_level in risk_dist:
            risk_dist[risk_level] += 1

        if s.full_result:
            try:
                full = json.loads(s.full_result)
                geo = full.get('geo', {})
                country = geo.get('country', '')
                if country:
                    geo_count += 1
                    country_stats[country]['count'] += 1
                    if s.ml_prediction == 'phishing':
                        country_stats[country]['phishing'] += 1
                    country_stats[country]['total_risk'] += (s.risk_score or 0)
            except Exception:
                pass

    # Sort countries by threat count
    top_countries = sorted(
        [{'country': k, **v, 'avg_risk': round(v['total_risk'] / max(v['count'], 1), 1)}
         for k, v in country_stats.items()],
        key=lambda x: x['count'],
        reverse=True
    )[:15]

    return jsonify({
        'total_scans': total,
        'geo_tagged': geo_count,
        'countries': len(country_stats),
        'risk_distribution': risk_dist,
        'top_countries': top_countries,
    })


@api_bp.route('/threat-map/recent')
def threat_map_recent():
    """
    Recent geo-tagged threats for the live feed sidebar.
    """
    limit = request.args.get('limit', 10, type=int)
    scans = EmailScanResult.query.filter(
        EmailScanResult.ml_prediction == 'phishing'
    ).order_by(
        EmailScanResult.timestamp.desc()
    ).limit(limit).all()

    recent = []
    for s in scans:
        if not s.full_result:
            continue
        try:
            full = json.loads(s.full_result)
            geo = full.get('geo', {})
            recent.append({
                'email_id': s.email_id or '',
                'from': full.get('from', ''),
                'subject': full.get('subject', ''),
                'country': geo.get('country', ''),
                'city': geo.get('city', ''),
                'risk_score': s.risk_score or 0,
                'risk_level': s.risk_level or 'Unknown',
                'timestamp': s.timestamp.isoformat() if s.timestamp else '',
            })
        except Exception:
            pass

    return jsonify({'recent': recent, 'count': len(recent)})


# ---------------------------------------------------------------------------
# Batch Email Scanner & Remediation Playbook APIs
# ---------------------------------------------------------------------------

@api_bp.route('/batch-scan', methods=['POST'])
def batch_scan():
    """
    Scan multiple emails in a single request.
    Accepts JSON: { "emails": [ { "headers": "...", "body": "...", "subject": "..." }, ... ] }
    """
    import asyncio
    from backend.services.email_scanner import scan_emails

    data = request.get_json(silent=True) or {}
    raw_emails = data.get('emails', [])
    if not raw_emails or not isinstance(raw_emails, list):
        return jsonify({'error': 'Invalid request format. Expected JSON with "emails" array.'}), 400

    if len(raw_emails) > 20:
        raw_emails = raw_emails[:20]

    prepared_emails = []
    for i, item in enumerate(raw_emails):
        if isinstance(item, str):
            prepared_emails.append({'headers': '', 'body': item, 'id': f'batch-{i+1}'})
        elif isinstance(item, dict):
            headers = item.get('headers', '')
            body = item.get('body', item.get('content', ''))
            subject = item.get('subject', '')
            if subject and 'Subject:' not in headers:
                headers = f"Subject: {subject}\n" + headers
            prepared_emails.append({
                'headers': headers,
                'body': body,
                'id': item.get('id', f'batch-{i+1}'),
                'subject': subject
            })

    loop = asyncio.new_event_loop()
    results = loop.run_until_complete(scan_emails(prepared_emails, limit=len(prepared_emails)))
    loop.close()

    total = len(results)
    phishing_count = sum(1 for r in results if r.get('ml', {}).get('prediction') == 'phishing')
    legitimate_count = total - phishing_count
    scores = [r.get('risk_assessment', {}).get('risk_score', 0) for r in results]
    avg_risk = round(sum(scores) / max(total, 1), 1)

    return jsonify({
        'total': total,
        'phishing_count': phishing_count,
        'legitimate_count': legitimate_count,
        'avg_risk_score': avg_risk,
        'results': results
    })


@api_bp.route('/remediation-playbook', methods=['POST'])
def remediation_playbook():
    """
    Generate SOC Incident Remediation Playbook for a scan result.
    Accepts JSON scan result object.
    """
    from backend.services.forensic_analyzer import ForensicAnalyzer

    scan_data = request.get_json(silent=True) or {}
    analyzer = ForensicAnalyzer()
    playbook = analyzer.generate_remediation_playbook(scan_data)
    return jsonify(playbook)


@api_bp.route('/campaigns')
def get_campaigns():
    """
    Aggregates threat scans into Threat Campaigns with MITRE ATT&CK Mapping.
    """
    scans = EmailScanResult.query.order_by(EmailScanResult.timestamp.desc()).all()

    domain_clusters = defaultdict(list)
    for s in scans:
        sender_domain = 'unknown'
        if s.full_result:
            try:
                full = json.loads(s.full_result)
                sender = full.get('from', '')
                if '@' in sender:
                    sender_domain = sender.split('@')[-1].lower()
            except Exception:
                pass

        if not sender_domain or sender_domain == 'unknown':
            sender_domain = (s.geo_country or 'global-threat') + '-campaign'

        domain_clusters[sender_domain].append(s)

    campaigns = []
    idx = 1
    for domain, group in domain_clusters.items():
        if len(group) == 0:
            continue
        phish_count = sum(1 for item in group if item.ml_prediction == 'phishing')
        avg_score = round(sum((item.risk_score or 0) for item in group) / len(group), 1)

        mitre_mapping = [
            {'id': 'T1566.002', 'name': 'Spearphishing Link', 'tactic': 'Initial Access'},
            {'id': 'T1583.001', 'name': 'Acquire Domains', 'tactic': 'Resource Development'},
            {'id': 'T1598.003', 'name': 'Spearphishing Service', 'tactic': 'Reconnaissance'},
        ]

        campaigns.append({
            'campaign_id': f'CMP-2026-{idx:03d}',
            'name': f'Operation {domain.replace(".", "_").upper()} Threat Infrastructure',
            'sender_domain': domain,
            'origin_country': group[0].geo_country or 'Unknown',
            'email_count': len(group),
            'phishing_count': phish_count,
            'avg_risk_score': avg_score,
            'risk_level': 'Critical' if avg_score >= 70 else ('High' if avg_score >= 50 else 'Medium'),
            'mitre_attack': mitre_mapping,
            'last_active': group[0].timestamp.isoformat() if group[0].timestamp else '',
        })
        idx += 1

    return jsonify({'campaigns': campaigns, 'total_campaigns': len(campaigns)})


@api_bp.route('/campaigns/search')
def ioc_search():
    """Global IOC search across all email scans, IPs, domains, and subjects."""
    q = request.args.get('q', '').strip().lower()
    if not q:
        return jsonify({'results': [], 'count': 0})

    scans = EmailScanResult.query.all()
    matches = []

    for s in scans:
        full = json.loads(s.full_result) if s.full_result else {}
        sender = full.get('from', '').lower()
        subject = full.get('subject', '').lower()
        ip = (s.geo_country or '') + (full.get('geo', {}).get('ip', ''))

        if q in sender or q in subject or q in ip.lower() or q in (s.email_id or '').lower():
            matches.append({
                'email_id': s.email_id,
                'subject': full.get('subject', ''),
                'from': full.get('from', ''),
                'risk_score': s.risk_score,
                'risk_level': s.risk_level,
                'ml_prediction': s.ml_prediction,
                'timestamp': s.timestamp.isoformat() if s.timestamp else '',
            })

    return jsonify({'results': matches, 'count': len(matches), 'query': q})


@api_bp.route('/soc/playbook', methods=['POST'])
def get_soc_playbook():
    """Generate YARA rules, SIGMA rules, STIX 2.1 bundles, and containment playbooks."""
    from backend.services.soc_playbook import generate_soc_playbook
    data = request.json or {}
    playbook = generate_soc_playbook(data)
    return jsonify(playbook)

