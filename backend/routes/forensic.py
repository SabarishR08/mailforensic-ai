"""Forensic analysis routes — .eml upload, header analysis, PDF reports"""
import json
import asyncio
import tempfile
import os
from email import message_from_string, policy
from email.parser import BytesParser
from flask import Blueprint, render_template, request, jsonify, send_file
from backend.services.forensic_analyzer import ForensicAnalyzer
from backend.services.geo_service import get_geo_service
from backend.services.risk_scoring import RiskScoringEngine
from backend.services.ml_predictor import get_ml_predictor
from backend.services.forensic_report import ForensicReportGenerator
from backend.services.threat_intelligence import unified_url_check
from backend.services.url_intelligence import URLAnalyzer
from backend.services.qr_service import QREmailAnalyzer
from backend.utils.url_utils import extract_urls
from backend.models import EmailScanResult, db
from backend.spa import spa_enabled, spa_index

forensic_bp = Blueprint('forensic', __name__)


# ---------------------------------------------------------------------------
# .eml Forensic Demo
# ---------------------------------------------------------------------------

@forensic_bp.route('/scan')
def forensic_scan_page():
    """Render the .eml upload page"""
    if spa_enabled():
        return spa_index()
    return render_template('forensic_eml.html')


@forensic_bp.route('/report/<int:scan_id>')
def forensic_drilldown(scan_id):
    if spa_enabled():
        return spa_index()
    scan = EmailScanResult.query.get_or_404(scan_id)
    full_result = json.loads(scan.full_result) if scan.full_result else {}
    return render_template('forensic_report.html', scan=scan, result=full_result)


@forensic_bp.route('/api/analyze', methods=['POST'])
def api_forensic_analyze():
    """Analyze raw email headers for forensic breakdown"""
    raw_headers = request.json.get('raw_headers', '') if request.is_json else ''
    if not raw_headers:
        return jsonify({'error': 'No headers provided'}), 400

    geo_service = get_geo_service()
    analyzer = ForensicAnalyzer()
    result = analyzer.analyze(raw_headers, geo_service=geo_service)
    return jsonify(result)


@forensic_bp.route('/api/analyze-eml', methods=['POST'])
def api_analyze_eml():
    """
    Accept a .eml file upload and run the full forensic analysis pipeline.
    No Gmail credentials needed — works entirely offline with a local file.
    
    Pipeline: parse .eml → extract QR codes → ML prediction → forensic header analysis
    → URL intelligence → threat intel → geo enrichment → risk scoring → full report JSON
    """
    attachments = []
    eml_text = ""

    # --- 1. Get the uploaded file ---
    if 'file' not in request.files:
        if request.is_json and request.json.get('eml_text'):
            eml_text = request.json['eml_text']
        else:
            return jsonify({'error': 'No .eml file uploaded and no eml_text provided'}), 400
    else:
        f = request.files['file']
        if not f.filename:
            return jsonify({'error': 'Empty filename'}), 400
        if not f.filename.lower().endswith('.eml'):
            return jsonify({'error': f'Expected .eml file, got: {f.filename}'}), 400
        eml_bytes = f.read()
        try:
            msg = BytesParser(policy=policy.default).parsebytes(eml_bytes)
            # Extract attachments
            for part in msg.walk():
                content_type = part.get_content_type()
                filename = part.get_filename()
                if content_type.startswith('image/') or (filename and any(filename.lower().endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.bmp', '.gif', '.webp'])):
                    try:
                        content_data = part.get_payload(decode=True)
                        if content_data:
                            attachments.append({'filename': filename or 'image.png', 'content': content_data})
                    except Exception:
                        pass
        except Exception as e:
            return jsonify({'error': f'Failed to parse .eml file: {e}'}), 400
        eml_text = eml_bytes.decode('utf-8', errors='replace')

    # --- 2. Parse the email for body text + metadata ---
    try:
        msg = message_from_string(eml_text)
    except Exception as e:
        return jsonify({'error': f'Failed to parse email: {e}'}), 400

    body = ''
    raw_body = ''
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == 'text/plain':
                body = part.get_content() if hasattr(part, 'get_content') else part.get_payload(decode=True).decode('utf-8', errors='replace')
            elif ct == 'text/html':
                raw_body = part.get_content() if hasattr(part, 'get_content') else part.get_payload(decode=True).decode('utf-8', errors='replace')
                if not body:
                    body = raw_body
    else:
        payload = msg.get_payload(decode=True)
        body = payload.decode('utf-8', errors='replace') if payload else str(msg)
        raw_body = body

    if not body.strip():
        body = msg.get('Subject', '(no body)')

    # --- 3. QR Code Extraction ---
    email_data = {
        'body': body,
        'raw_body': raw_body,
        'attachments': attachments
    }
    qr_analysis = QREmailAnalyzer.extract_qr_from_email(email_data)

    # --- 4. Run the full analysis pipeline ---
    ml_predictor = get_ml_predictor()
    geo_service = get_geo_service()
    forensic = ForensicAnalyzer()

    # 4a. ML Prediction
    ml_prediction, ml_confidence = (
        ml_predictor.predict_email(body)
        if ml_predictor.is_email_model_loaded()
        else ('unknown', 0.5)
    )

    # 4b. Forensic header analysis with geo enrichment
    forensic_result = forensic.analyze(eml_text, geo_service=geo_service)

    # 4c. Extract all URLs (body, headers, QR payloads)
    body_urls = extract_urls(body + ' ' + raw_body)
    header_urls = extract_urls(eml_text)
    qr_urls = qr_analysis.get('urls_found', [])
    all_urls = list(dict.fromkeys(body_urls + header_urls + qr_urls))

    # 4d. URL Intelligence Analysis
    url_intel_results = {}
    max_url_intel_score = 0
    url_threats_list = []
    for url in all_urls[:10]:
        try:
            intel = URLAnalyzer.full_analysis(url, check_redirects=False)
            url_intel_results[url] = intel
            if intel.get('risk_score', 0) > max_url_intel_score:
                max_url_intel_score = intel.get('risk_score', 0)
            if intel.get('threats'):
                url_threats_list.extend(intel['threats'])
        except Exception:
            pass

    url_intelligence_summary = {
        'total_urls': len(all_urls),
        'max_risk_score': max_url_intel_score,
        'url_threats': list(dict.fromkeys(url_threats_list)),
        'details': url_intel_results,
    }

    # 4e. Threat Intelligence (VT, SafeBrowsing, RDAP)
    url_results = {}
    max_ti_score = 0
    if all_urls:
        try:
            loop = asyncio.new_event_loop()
            tasks = [unified_url_check(url) for url in all_urls[:5]]
            results = loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
            loop.close()
            for url, result in zip(all_urls[:5], results):
                if not isinstance(result, Exception):
                    url_results[url] = result
                    ti = result.get('threat_score', 0)
                    if ti > max_ti_score:
                        max_ti_score = ti
        except Exception:
            pass

    # 4f. Geo enrichment of sender IP & cross-border payload infrastructure correlation
    origin_ip = forensic_result.get('routing', {}).get('origin_ip')
    geo_data = {}
    geo_correlation = {}
    if origin_ip:
        try:
            geo_data = geo_service.lookup_ip(origin_ip)
        except Exception:
            pass

    if geo_data and all_urls:
        try:
            geo_correlation = geo_service.correlate_sender_with_payload(geo_data, all_urls)
        except Exception:
            pass

    # 4g. Unified Risk Scoring
    risk_assessment = RiskScoringEngine.calculate({
        'ml_result': {'prediction': ml_prediction, 'confidence': ml_confidence},
        'threat_intel': {'threat_score': max_ti_score},
        'url_intelligence': url_intelligence_summary,
        'qr_analysis': qr_analysis,
        'forensic': forensic_result,
        'geo_data': geo_data,
        'geo_correlation': geo_correlation,
        'content_analysis': {'nlp_result': {}},
    })

    # --- 5. Assemble full report ---
    report = {
        'email_id': msg.get('Message-ID', 'unknown'),
        'subject': msg.get('Subject', ''),
        'from': msg.get('From', ''),
        'to': msg.get('To', ''),
        'date': msg.get('Date', ''),
        'body_preview': body[:500],
        'body_length': len(body),
        'urls_found': all_urls,
        'ml': {
            'prediction': ml_prediction,
            'confidence': round(ml_confidence, 4),
            'model_loaded': ml_predictor.is_email_model_loaded(),
        },
        'forensic': forensic_result,
        'url_intelligence': url_intelligence_summary,
        'qr_analysis': qr_analysis,
        'url_results': url_results,
        'geo': geo_data,
        'geo_correlation': geo_correlation,
        'risk_assessment': risk_assessment,
    }

    # --- 6. Persist to DB ---
    try:
        scan = EmailScanResult(
            email_id=report['email_id'],
            ml_prediction=ml_prediction,
            ml_confidence=ml_confidence,
            risk_score=risk_assessment.get('risk_score', 0),
            risk_level=risk_assessment.get('risk_level', 'Unknown'),
            forensic_trust_score=forensic_result.get('trust_score', 0),
            geo_country=geo_data.get('country_code', ''),
            origin_ip=origin_ip or '',
            full_result=json.dumps(report, default=str),
        )
        db.session.add(scan)
        db.session.commit()
        report['scan_id'] = scan.id
    except Exception:
        db.session.rollback()

    return jsonify(report)


@forensic_bp.route('/api/report/pdf/<int:scan_id>')
def generate_pdf(scan_id):
    """Generate forensic PDF report for a scan result"""
    scan = EmailScanResult.query.get_or_404(scan_id)
    full_result = json.loads(scan.full_result) if scan.full_result else {}

    filepath = ForensicReportGenerator.generate_report(full_result)
    return send_file(filepath, as_attachment=True, download_name='forensic_report.pdf')


@forensic_bp.route('/api/report/<int:scan_id>')
def api_report_json(scan_id):
    """Return a persisted scan's report as JSON (used by the React SPA)."""
    scan = EmailScanResult.query.get_or_404(scan_id)
    full_result = json.loads(scan.full_result) if scan.full_result else {}
    return jsonify({'scan': scan.to_dict(), 'result': full_result})
