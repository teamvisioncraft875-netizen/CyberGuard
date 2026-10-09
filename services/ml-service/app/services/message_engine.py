"""
CYBERGUARD Threat Analysis — Message & Phishing Detection Engine
Evaluates text for phishing, social engineering, urgency cues, and adversarial prompt injections.
"""

import json
import logging
import os
import re
from typing import Any, Dict

from app.schemas.analyze import (
    MessageAnalyzeRequest,
    UnifiedAnalysisResponse,
    RiskLevel,
)
from app.prompts.phishing import (
    SYSTEM_PROMPT_VERSION,
    LLM_MAX_TOKENS,
    LLM_REQUEST_TIMEOUT_SECONDS,
    PHISHING_SYSTEM_PROMPT,
    sanitize_message_input,
)

import joblib
from pathlib import Path
from typing import Tuple, Optional

logger = logging.getLogger("cyberguard.message_engine")

_MODEL_DIR = Path(__file__).resolve().parents[1] / "models" / "phishing"
_CLASSIFIER_PATH = _MODEL_DIR / "phishing_classifier_v1.0.0.joblib"
_VECTORIZER_PATH = _MODEL_DIR / "phishing_vectorizer_v1.0.0.joblib"
_METADATA_PATH = _MODEL_DIR / "phishing_metadata_v1.0.0.json"

_CACHED_MODEL = None
_CACHED_VECTORIZER = None
_CACHED_METADATA = None


def _get_phishing_model() -> Tuple[Optional[Any], Optional[Any], Optional[Dict[str, Any]]]:
    """Lazy loader for trained supervised phishing classifier, vectorizer, and metadata."""
    global _CACHED_MODEL, _CACHED_VECTORIZER, _CACHED_METADATA
    if _CACHED_MODEL is None and _CLASSIFIER_PATH.exists() and _VECTORIZER_PATH.exists():
        try:
            _CACHED_MODEL = joblib.load(_CLASSIFIER_PATH)
            _CACHED_VECTORIZER = joblib.load(_VECTORIZER_PATH)
            if _METADATA_PATH.exists():
                with open(_METADATA_PATH, "r", encoding="utf-8") as f:
                    _CACHED_METADATA = json.load(f)
            logger.info("Successfully loaded supervised Phishing classifier v1.0.0")
        except Exception as e:
            logger.warning(f"Failed to load supervised phishing model: {e}")
            _CACHED_MODEL = None
            _CACHED_VECTORIZER = None
            _CACHED_METADATA = None
    return _CACHED_MODEL, _CACHED_VECTORIZER, _CACHED_METADATA


def _call_llm_if_available(sanitized_text: str) -> Dict[str, Any] | None:
    """
    Attempts to call an upstream LLM (OpenAI / Groq) if credentials exist in the environment.
    Enforces explicit max_tokens cap, versioned system prompt, and sandboxed prompt input.
    """
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("GROQ_API_KEY")
    if not api_key:
        return None

    try:
        if os.getenv("OPENAI_API_KEY"):
            from openai import OpenAI
            client = OpenAI(api_key=api_key, timeout=LLM_REQUEST_TIMEOUT_SECONDS)
            model_name = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        else:
            from groq import Groq
            client = Groq(api_key=api_key, timeout=LLM_REQUEST_TIMEOUT_SECONDS)
            model_name = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")

        user_content = (
            f"<untrusted_user_message>\n"
            f"{sanitized_text}\n"
            f"</untrusted_user_message>\n\n"
            f"Analyze the message above and respond strictly with valid JSON."
        )

        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": PHISHING_SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            max_tokens=LLM_MAX_TOKENS,
            temperature=0.0,
            response_format={"type": "json_object"} if hasattr(client, "chat") else None,
        )

        raw_output = response.choices[0].message.content
        if raw_output:
            data = json.loads(raw_output)
            return data
    except Exception as exc:
        logger.warning(f"Upstream LLM invocation failed or timed out: {exc}. Falling back to heuristic classifier.")
        return None

    return None


def analyze_message(request: MessageAnalyzeRequest) -> UnifiedAnalysisResponse:
    """
    Evaluates message text for phishing intent, urgency cues, credential theft, and brand spoofing.
    Implements prompt injection defense and versioned LLM capabilities with graceful fallback.
    """
    # 1. Basic input sanitization & prompt injection resistance
    sanitized_text, injection_detected = sanitize_message_input(request.text)

    # Empty text guard
    if not sanitized_text:
        return UnifiedAnalysisResponse(
            risk_level=RiskLevel.SAFE,
            risk_score=0,
            explanation="Empty message content provided; no threat indicators detected.",
            signals={
                "urgency_score": 0.0,
                "credential_solicitation": False,
                "brand_targeted": None,
                "contains_url": False,
                "prompt_injection_detected": False,
                "model_type": "empty_input",
                "source_type": request.source_type.value,
            },
            recommended_actions=["No action required; empty input."],
            confidence_score=1.0,
        )

    # If active adversarial injection detected, immediately flag
    if injection_detected:
        return UnifiedAnalysisResponse(
            risk_level=RiskLevel.HIGH,
            risk_score=90,
            explanation="Adversarial prompt injection pattern detected: Message attempts to override AI instructions.",
            signals={
                "urgency_score": 0.95,
                "credential_solicitation": False,
                "brand_targeted": None,
                "prompt_injection_detected": True,
                "model_type": f"sanitizer_guardrail_v{SYSTEM_PROMPT_VERSION}",
                "source_type": request.source_type.value,
            },
            recommended_actions=[
                "Do not process or forward message",
                "Flag message to security team for adversarial review",
            ],
            confidence_score=0.97,
        )

    # 2. Attempt LLM-based evaluation if an API key is provided
    llm_result = _call_llm_if_available(sanitized_text)
    if llm_result:
        try:
            risk_str = str(llm_result.get("risk_level", "High")).capitalize()
            risk_level_enum = RiskLevel(risk_str) if risk_str in RiskLevel._value2member_map_ else RiskLevel.HIGH
            return UnifiedAnalysisResponse(
                risk_level=risk_level_enum,
                risk_score=int(llm_result.get("risk_score", 80)),
                explanation=str(llm_result.get("explanation", "Potential security threat detected in message content.")),
                signals=dict(llm_result.get("signals", {})),
                recommended_actions=list(llm_result.get("recommended_actions", ["Do not click links; report message"])),
                confidence_score=float(llm_result.get("confidence_score", 0.90)),
            )
        except Exception as parse_err:
            logger.warning(f"Failed to parse LLM structured output: {parse_err}. Falling back to rule-based engine.")

    # 3. Supervised ML Classifier (Calibrated LinearSVC trained on Nazario/Nigerian/CEAS/Enron)
    model, vectorizer, meta = _get_phishing_model()

    text_lower = sanitized_text.lower()

    # Heuristic XAI cues (Urgency, Credential solicitation, Brand targeting, Links)
    urgency_terms = [
        "urgent", "immediately", "account locked", "suspended", "unauthorized",
        "action required", "within 24 hours", "within 1 hour", "limited time",
        "verify your identity", "security alert"
    ]
    urgency_matches = [term for term in urgency_terms if term in text_lower]
    urgency_score = min(1.0, len(urgency_matches) * 0.35 + (0.3 if "urgent" in text_lower or "immediately" in text_lower else 0.0))

    credential_terms = [
        "password", "login", "credentials", "banking", "ssn", "pin", "verify account",
        "update payment", "confirm credentials", "access code", "two-factor"
    ]
    credential_matches = [term for term in credential_terms if term in text_lower]
    credential_solicitation = len(credential_matches) > 0

    brands = {
        "chase": "Chase Bank",
        "paypal": "PayPal",
        "bank of america": "Bank of America",
        "wells fargo": "Wells Fargo",
        "microsoft": "Microsoft",
        "apple": "Apple",
        "google": "Google",
        "amazon": "Amazon",
        "netflix": "Netflix",
    }
    targeted_brand = next((name for k, name in brands.items() if k in text_lower), None)
    has_link = bool(re.search(r"https?://\S+|www\.\S+", sanitized_text))

    ml_prob = None
    threshold = 0.36
    if model is not None and vectorizer is not None:
        try:
            X_vec = vectorizer.transform([sanitized_text])
            ml_prob = float(model.predict_proba(X_vec)[0, 1])
            threshold = float(meta.get("operating_threshold", 0.36)) if meta else 0.36
        except Exception as ml_err:
            logger.warning(f"Supervised model inference failed: {ml_err}. Falling back to pure heuristics.")
            ml_prob = None

    # Calibrate unified score and tier
    if ml_prob is not None:
        is_threat = ml_prob >= threshold
        if is_threat:
            # Scaled 70..100 based on probability and compounding risk cues
            base_score = 70 + int((ml_prob - threshold) / (1.0 - threshold) * 20)
            if credential_solicitation or targeted_brand:
                base_score += 10
            score = min(100, max(70, base_score))
        else:
            # Scaled 5..65 based on probability and heuristic cues
            base_score = int((ml_prob / max(threshold, 0.01)) * 40)
            if urgency_score > 0.3:
                base_score += 15
            if has_link:
                base_score += 10
            score = min(65, max(5, base_score))
    else:
        # Fallback heuristic calculation if model unreadable
        score = 15
        if urgency_score > 0.3:
            score += int(urgency_score * 35)
        if credential_solicitation:
            score += 30
        if targeted_brand:
            score += 15
        if has_link:
            score += 10
        score = min(100, max(0, score))

    # Deep inspection of embedded URLs
    embedded_urls = re.findall(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", sanitized_text)
    highest_embedded_url_risk = None
    malicious_url_context = None

    if embedded_urls:
        try:
            from app.services.url_engine import analyze_url
            from app.schemas.analyze import UrlAnalyzeRequest
            for raw_u in embedded_urls:
                norm_u = raw_u if raw_u.startswith("http") else f"http://{raw_u}"
                u_res = analyze_url(UrlAnalyzeRequest(url=norm_u))
                if u_res.risk_level == RiskLevel.CRITICAL:
                    highest_embedded_url_risk = RiskLevel.CRITICAL
                    malicious_url_context = (raw_u, u_res)
                    break
                elif u_res.risk_level == RiskLevel.HIGH and highest_embedded_url_risk != RiskLevel.CRITICAL:
                    highest_embedded_url_risk = RiskLevel.HIGH
                    malicious_url_context = (raw_u, u_res)
        except Exception as u_err:
            logger.debug(f"Embedded URL analysis note: {u_err}")

    # Compound threat escalation if embedded URL is malicious
    if highest_embedded_url_risk == RiskLevel.CRITICAL and malicious_url_context:
        bad_url, url_eval = malicious_url_context
        score = max(score, url_eval.risk_score, 95)
        risk_level = RiskLevel.CRITICAL
        explanation = f"Critical Threat: Message contains confirmed malicious phishing URL ({bad_url}): {url_eval.explanation}"
        actions = [
            "Do not click any embedded links",
            "Quarantine message immediately across enterprise mail gateway",
            "Block destination URL network-wide on gateway and DNS",
        ]
    elif highest_embedded_url_risk == RiskLevel.HIGH and malicious_url_context and score < 80:
        bad_url, url_eval = malicious_url_context
        score = max(score, url_eval.risk_score, 80)
        risk_level = RiskLevel.HIGH
        explanation = f"High Risk: Message contains suspicious URL ({bad_url}): {url_eval.explanation}"
    # Promotional / Marketing Guard:
    # If the message contains promotional urgency phrases but NO credential solicitation,
    # NO malicious embedded URLs, and the supervised model probability does not cross the threat threshold,
    # cap the score at LOW (<= 35) to prevent legitimate sales/marketing alerts from triggering phishing alarms.
    if not credential_solicitation and not highest_embedded_url_risk and (ml_prob is None or ml_prob < threshold):
        if not targeted_brand and score >= 50:
            score = 35

    if score >= 80:
        risk_level = RiskLevel.HIGH if score < 95 else RiskLevel.CRITICAL
        explanation = (
            f"Message exhibits extreme urgency cues demanding credential verification "
            f"and targets {targeted_brand or 'a recognized provider'}."
            if targeted_brand else
            "Supervised analysis identified high-probability phishing or social engineering threat targeting credentials or accounts."
        )
        actions = [
            "Do not click any embedded links",
            "Quarantine message and flag domain to enterprise gateway",
        ]
    elif score >= 50:
        risk_level = RiskLevel.MEDIUM
        explanation = "Message contains moderate urgency language, unexpected financial requests, or unfamiliar notices."
        actions = ["Exercise caution before taking action on this message"]
    elif score >= 25:
        risk_level = RiskLevel.LOW
        explanation = "Low Risk: Minor marketing urgency terms detected with no credential solicitation."
        actions = ["Review message normally"]
    else:
        risk_level = RiskLevel.SAFE
        explanation = "Safe: No phishing, credential harvesting, or urgency indicators detected."
        actions = ["No action required"]

    confidence = round(ml_prob if (ml_prob and ml_prob >= 0.5) else (1.0 - ml_prob if ml_prob else 0.88), 4)

    return UnifiedAnalysisResponse(
        risk_level=risk_level,
        risk_score=score,
        explanation=explanation,
        signals={
            "ml_threat_probability": round(ml_prob, 4) if ml_prob is not None else None,
            "ml_decision": "threat" if (ml_prob is not None and ml_prob >= threshold) else "benign",
            "operating_threshold": threshold,
            "urgency_score": round(urgency_score, 2),
            "urgency_language_detected": urgency_score > 0.3,
            "credential_solicitation": credential_solicitation,
            "domain_mismatch": bool(has_link and targeted_brand),
            "brand_targeted": targeted_brand,
            "contains_url": has_link,
            "prompt_injection_detected": False,
            "model_type": "supervised_calibrated_linearsvc_v1.0.0" if ml_prob is not None else f"heuristic_fallback_v{SYSTEM_PROMPT_VERSION}",
            "source_type": request.source_type.value,
        },
        recommended_actions=actions,
        confidence_score=confidence,
    )

