"""
Multi-LLM AI Fallback Service & Threat Fusion Engine
Implements strict priority fallback cascade:
  1. Groq (openai/gpt-oss-20b or fast open-weights LLMs)
  2. Google Gemini (gemini-3.6-flash)
  3. NVIDIA NIM (meta/llama-3.2-11b-vision-instruct)
  4. Local ML Ensemble (XGBoost + LightGBM + DistilBERT)
"""

import os
import json
import re
import httpx
import logging
from typing import Dict, Any, Optional
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_API_KEY_FALLBACK = os.getenv("GROQ_API_KEY_FALLBACK")
GROQ_KEYS = [k for k in [GROQ_API_KEY, GROQ_API_KEY_FALLBACK] if k]

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY")



logger = logging.getLogger(__name__)


def clean_json_response(raw_text: str) -> Optional[Dict[str, Any]]:
    """Robustly extract and clean JSON from LLM outputs (handles <think> tags, markdown fences, etc.)"""
    if not raw_text or not isinstance(raw_text, str):
        return None
    try:
        # Strip thinking tags if generated
        text = re.sub(r"<think>.*?</think>", "", raw_text, flags=re.DOTALL)
        # Strip markdown fences
        text = text.replace("```json", "").replace("```", "").strip()
        # Find json object boundaries
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end >= start:
            text = text[start:end + 1]
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except Exception as e:
        logger.debug(f"JSON parsing error: {e} on text snippet: {raw_text[:120]}")
    return None


async def classify_with_groq(email_text: str) -> Optional[Dict[str, Any]]:
    """Priority 1: Groq API (tries primary key, then fallback account key if rate limited or failed)"""
    if not GROQ_KEYS:
        return None
    url = "https://api.groq.com/openai/v1/chat/completions"
    prompt = (
        f'Analyze this email and classify it. Respond ONLY in JSON:\n'
        f'{{"category": "Phishing|Spam|Legitimate|Suspicious", "reason": "brief explanation", "confidence": 0.0-1.0}}\n\n'
        f'Email:\n{email_text[:3000]}'
    )
    payload = {
        "model": "openai/gpt-oss-20b",
        "messages": [
            {"role": "system", "content": "You are a cybersecurity AI. Respond ONLY with valid raw JSON."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 250,
        "temperature": 0.1
    }

    for key_idx, key in enumerate(GROQ_KEYS):
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json"
        }
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code == 200:
                    msg = resp.json()["choices"][0]["message"]
                    content = msg.get("content") or msg.get("reasoning") or ""
                    parsed = clean_json_response(content)
                    if parsed and "category" in parsed:
                        parsed["provider"] = "groq"
                        parsed["model"] = "openai/gpt-oss-20b"
                        return parsed
                else:
                    logger.warning(f"Groq (key {key_idx+1}) failed status={resp.status_code}: {resp.text[:100]}")
        except Exception as e:
            logger.warning(f"Groq (key {key_idx+1}) request error: {e}")
    return None



async def classify_with_gemini(email_text: str) -> Optional[Dict[str, Any]]:
    """Priority 2: Google Gemini (gemini-3.6-flash)"""
    if not GEMINI_API_KEY:
        return None
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key={GEMINI_API_KEY}"
    prompt = (
        f'Analyze this email and classify it. Respond ONLY in JSON:\n'
        f'{{"category": "Phishing|Spam|Legitimate|Suspicious", "reason": "brief explanation", "confidence": 0.0-1.0}}\n\n'
        f'Email:\n{email_text[:3000]}'
    )
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                url,
                json={"contents": [{"parts": [{"text": prompt}]}]},
                headers={"Content-Type": "application/json"}
            )
            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    # Find first text part
                    for p in parts:
                        if "text" in p:
                            parsed = clean_json_response(p["text"])
                            if parsed and "category" in parsed:
                                parsed["provider"] = "gemini"
                                parsed["model"] = "gemini-3.6-flash"
                                return parsed
            else:
                logger.warning(f"Gemini classification failed status={resp.status_code}: {resp.text[:100]}")
    except Exception as e:
        logger.warning(f"Gemini classification request error: {e}")
    return None


async def classify_with_nvidia(email_text: str) -> Optional[Dict[str, Any]]:
    """Priority 3: NVIDIA NIM (meta/llama-3.2-11b-vision-instruct)"""
    if not NVIDIA_API_KEY:
        return None
    url = "https://integrate.api.nvidia.com/v1/chat/completions"
    prompt = (
        f'Analyze this email and classify it. Respond ONLY in JSON:\n'
        f'{{"category": "Phishing|Spam|Legitimate|Suspicious", "reason": "brief explanation", "confidence": 0.0-1.0}}\n\n'
        f'Email:\n{email_text[:3000]}'
    )
    headers = {
        "Authorization": f"Bearer {NVIDIA_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "meta/llama-3.2-11b-vision-instruct",
        "messages": [
            {"role": "system", "content": "You are a cybersecurity AI. Respond ONLY with valid raw JSON."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 250,
        "temperature": 0.1
    }
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code == 200:
                content = resp.json()["choices"][0]["message"]["content"]
                parsed = clean_json_response(content)
                if parsed and "category" in parsed:
                    parsed["provider"] = "nvidia"
                    parsed["model"] = "meta/llama-3.2-11b-vision-instruct"
                    return parsed
            else:
                logger.warning(f"NVIDIA classification failed status={resp.status_code}: {resp.text[:100]}")
    except Exception as e:
        logger.warning(f"NVIDIA classification request error: {e}")
    return None


async def classify_email_nlp(email_text: str) -> dict:
    """
    Unified Multi-LLM API cascade classifier:
      1. Groq
      2. Gemini
      3. NVIDIA NIM
      4. Fallback default if all external APIs are unreachable/exhausted
    """
    # 1. Try Groq
    res = await classify_with_groq(email_text)
    if res:
        return res

    # 2. Try Gemini
    res = await classify_with_gemini(email_text)
    if res:
        return res

    # 3. Try NVIDIA
    res = await classify_with_nvidia(email_text)
    if res:
        return res

    # 4. Fallback
    logger.info("All LLM providers exhausted; falling back to heuristic/ML pipeline")
    return {
        "category": "Unknown",
        "reason": "External LLM APIs currently unavailable; falling back to local ML ensemble",
        "confidence": 0.0,
        "provider": "ml_ensemble_fallback"
    }


async def analyze_threat_fusion(analysis_data: dict) -> dict:
    """
    Fuse ML prediction + threat intel + geo + forensic into AI-enhanced assessment
    using multi-LLM fallback: Groq -> Gemini -> NVIDIA.
    """
    data_str = json.dumps(analysis_data, indent=2, default=str)[:4000]
    prompt = (
        f'You are a cybersecurity threat analyst. Analyze this email threat data and provide an enhanced risk assessment.\n\n'
        f'Data:\n{data_str}\n\n'
        f'Respond ONLY in JSON:\n'
        f'{{"summary": "one paragraph threat summary", "enhanced_risk_score": 0-100, "key_findings": ["finding1", "finding2"], "recommendations": ["action1", "action2"]}}'
    )

    # 1. Try Groq (iterating keys)
    for key_idx, key in enumerate(GROQ_KEYS):
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                    json={
                        "model": "openai/gpt-oss-20b",
                        "messages": [
                            {"role": "system", "content": "You are a cybersecurity AI. Respond ONLY with valid raw JSON."},
                            {"role": "user", "content": prompt}
                        ],
                        "max_tokens": 400,
                        "temperature": 0.1
                    }
                )
                if resp.status_code == 200:
                    parsed = clean_json_response(resp.json()["choices"][0]["message"]["content"])
                    if parsed and "summary" in parsed:
                        parsed["provider"] = "groq"
                        return parsed
        except Exception as e:
            logger.warning(f"Groq threat fusion failed (key {key_idx+1}): {e}")


    # 2. Try Gemini
    if GEMINI_API_KEY:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key={GEMINI_API_KEY}"
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.post(
                    url,
                    json={"contents": [{"parts": [{"text": prompt}]}]},
                    headers={"Content-Type": "application/json"}
                )
                if resp.status_code == 200:
                    candidates = resp.json().get("candidates", [])
                    if candidates:
                        for p in candidates[0].get("content", {}).get("parts", []):
                            if "text" in p:
                                parsed = clean_json_response(p["text"])
                                if parsed and "summary" in parsed:
                                    parsed["provider"] = "gemini"
                                    return parsed
        except Exception as e:
            logger.warning(f"Gemini threat fusion failed: {e}")

    # 3. Try NVIDIA
    if NVIDIA_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.post(
                    "https://integrate.api.nvidia.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {NVIDIA_API_KEY}", "Content-Type": "application/json"},
                    json={
                        "model": "meta/llama-3.2-11b-vision-instruct",
                        "messages": [
                            {"role": "system", "content": "You are a cybersecurity AI. Respond ONLY with valid raw JSON."},
                            {"role": "user", "content": prompt}
                        ],
                        "max_tokens": 400,
                        "temperature": 0.1
                    }
                )
                if resp.status_code == 200:
                    parsed = clean_json_response(resp.json()["choices"][0]["message"]["content"])
                    if parsed and "summary" in parsed:
                        parsed["provider"] = "nvidia"
                        return parsed
        except Exception as e:
            logger.warning(f"NVIDIA threat fusion failed: {e}")

    return {'summary': 'Automated heuristic & ML forensic analysis complete.', 'enhanced_risk': None}


def extract_heuristic_cognitive_vectors(email_text: str) -> Dict[str, Any]:
    """Deterministic fallback for cognitive vectors when LLM APIs are offline."""
    text_lower = (email_text or "").lower()
    
    # Check financial coercion & wire transfer indicators
    fin_patterns = [
        r'\bwire\s+transfer\b', r'\bbeneficiary\s+bank\b', r'\brouting\s+number\b',
        r'\bswift\b', r'\biban\b', r'\bgift\s+card\b', r'\bpayroll\b',
        r'\binvoice\s*#?\d+\b', r'\bbank\s+account\b', r'\bconfidential\s+acquisition\b',
        r'\bprocess\s+payment\b', r'\bbitcoin\b', r'\bcrypto\b'
    ]
    financial_coercion = any(re.search(p, text_lower) for p in fin_patterns)
    
    # Check authority impersonation
    auth_patterns = [
        (r'\bceo\b|\bchief\s+executive\b|\bpresident\b', 'CEO/Executive'),
        (r'\bcfo\b|\btreasurer\b|\bfinance\s+director\b', 'CFO/Finance'),
        (r'\bit\s+support\b|\bsecurity\s+team\b|\bsystem\s+administrator\b', 'IT/Security'),
        (r'\bpaypal\b|\bbank\s+of\s+america\b|\bchase\b|\bwellsfargo\b', 'Financial Institution'),
        (r'\birs\b|\btax\s+authority\b|\blegal\s+counsel\b', 'Legal/Government')
    ]
    authority = 'None'
    for pat, label in auth_patterns:
        if re.search(pat, text_lower):
            authority = label
            break
            
    # Check administrative purity (routine statements, notifications, receipts with NO demands)
    admin_patterns = [
        r'\bmonthly\s+account\s+statement\b', r'\byour\s+statement\s+is\s+now\s+available\b',
        r'\bno\s+action\s+is\s+required\b', r'\bofficial\s+website\s+or\s+mobile\s+application\b',
        r'\bwelcome\s+to\b', r'\bapplication\s+for\b', r'\bdiscussion\s+or\s+demonstration\b',
        r'\bsecurity\s+patches\s+applied\b', r'\bweekly\s+summary\b'
    ]
    admin_matches = sum(1 for p in admin_patterns if re.search(p, text_lower))
    administrative_purity = min(10, admin_matches * 3)
    
    # Urgency score
    urgency_words = ['urgent', 'immediately', 'within 24 hours', 'action required', 'account suspended', 'limited access', 'critical']
    urgency_count = sum(1 for w in urgency_words if w in text_lower)
    urgency_score = min(10, urgency_count * 3)
    
    # Determine verdict
    if financial_coercion and (authority in ('CEO/Executive', 'CFO/Finance') or 'confidential' in text_lower):
        verdict = 'conversational_bec'
        evasion_analysis = 'Detected Business Email Compromise (BEC) pattern: Executive wire/financial demand masked with conversational tone.'
    elif administrative_purity >= 6 and not financial_coercion:
        verdict = 'benign_administrative'
        evasion_analysis = 'Routine administrative correspondence without coercive demands.'
    elif urgency_score >= 6 and ('verify' in text_lower or 'password' in text_lower or 'login' in text_lower):
        verdict = 'credential_harvest'
        evasion_analysis = 'High-pressure urgency coupled with authentication credential solicitation.'
    else:
        verdict = 'neutral'
        evasion_analysis = 'Standard communication flow.'
        
    return {
        'urgency_score': urgency_score,
        'financial_coercion': financial_coercion,
        'authority_impersonation': authority,
        'administrative_purity': administrative_purity,
        'deception_verdict': verdict,
        'evasion_analysis': evasion_analysis,
        'provider': 'cognitive_heuristic_engine'
    }


async def extract_cognitive_vectors(email_text: str) -> Dict[str, Any]:
    """
    Extract cognitive manipulation and psychological vectors from email text
    using Groq / NVIDIA NIM / Gemini with fallback to deterministic cognitive heuristics.
    """
    if not email_text or not email_text.strip():
        return extract_heuristic_cognitive_vectors("")

    prompt = (
        "You are an expert cognitive cybersecurity forensic analyst.\n"
        "Analyze this email text for social engineering, urgency, financial demands, and administrative markers.\n"
        "Respond ONLY with valid JSON matching this schema:\n"
        "{\n"
        '  "urgency_score": 0-10,\n'
        '  "financial_coercion": true/false,\n'
        '  "authority_impersonation": "None|CEO/Executive|CFO/Finance|IT/Security|Financial Institution|Legal/Government",\n'
        '  "administrative_purity": 0-10,\n'
        '  "deception_verdict": "benign_administrative|conversational_bec|credential_harvest|neutral",\n'
        '  "evasion_analysis": "one sentence explaining the social engineering or administrative intent"\n'
        "}\n\n"
        f"Email Text:\n{email_text[:2500]}"
    )

    # 1. Try Groq
    for key in GROQ_KEYS:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                    json={
                        "model": "openai/gpt-oss-20b",
                        "messages": [
                            {"role": "system", "content": "You are a cybersecurity AI. Output ONLY valid JSON."},
                            {"role": "user", "content": prompt}
                        ],
                        "max_tokens": 200,
                        "temperature": 0.1
                    }
                )
                if resp.status_code == 200:
                    msg = resp.json()["choices"][0]["message"]
                    content = msg.get("content") or msg.get("reasoning") or ""
                    parsed = clean_json_response(content)
                    if parsed and "deception_verdict" in parsed:
                        parsed["provider"] = "groq_openai_gpt_oss_20b"
                        return parsed
        except Exception as e:
            logger.debug(f"Groq cognitive vector extraction error: {e}")

    # 2. Try NVIDIA NIM
    if NVIDIA_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    "https://integrate.api.nvidia.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {NVIDIA_API_KEY}", "Content-Type": "application/json"},
                    json={
                        "model": "meta/llama-3.2-11b-vision-instruct",
                        "messages": [
                            {"role": "system", "content": "You are a cybersecurity AI. Output ONLY valid JSON."},
                            {"role": "user", "content": prompt}
                        ],
                        "max_tokens": 200,
                        "temperature": 0.1
                    }
                )
                if resp.status_code == 200:
                    parsed = clean_json_response(resp.json()["choices"][0]["message"]["content"])
                    if parsed and "deception_verdict" in parsed:
                        parsed["provider"] = "nvidia_llama_3.2"
                        return parsed
        except Exception as e:
            logger.debug(f"NVIDIA cognitive vector extraction error: {e}")

    # 3. Fallback to deterministic heuristic cognitive engine
    return extract_heuristic_cognitive_vectors(email_text)

