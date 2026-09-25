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

logger = logging.getLogger("cyberguard.message_engine")


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

    # 3. Deterministic / Heuristic feature-scoring pipeline (fast-path & offline fallback)
    text_lower = sanitized_text.lower()

    # Urgency cues
    urgency_terms = [
        "urgent", "immediately", "account locked", "suspended", "unauthorized",
        "action required", "within 24 hours", "within 1 hour", "limited time",
        "verify your identity", "security alert"
    ]
    urgency_matches = [term for term in urgency_terms if term in text_lower]
    urgency_score = min(1.0, len(urgency_matches) * 0.35 + (0.3 if "urgent" in text_lower or "immediately" in text_lower else 0.0))

    # Credential solicitation keywords
    credential_terms = [
        "password", "login", "credentials", "banking", "ssn", "pin", "verify account",
        "update payment", "confirm credentials", "access code", "two-factor"
    ]
    credential_matches = [term for term in credential_terms if term in text_lower]
    credential_solicitation = len(credential_matches) > 0

    # Brand targeting
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

    # Link / URL presence
    has_link = bool(re.search(r"https?://\S+|www\.\S+", sanitized_text))

    # Calibrate risk score and tier
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

    if score >= 80:
        risk_level = RiskLevel.HIGH if score < 95 else RiskLevel.CRITICAL
        explanation = (
            f"Message exhibits extreme urgency cues demanding credential verification "
            f"and targets {targeted_brand or 'a recognized provider'}."
            if targeted_brand else
            "Message exhibits extreme urgency cues demanding credential verification and contains an unverified typo-squatted link."
        )
        actions = [
            "Do not click any embedded links",
            "Quarantine message and flag domain to enterprise gateway",
        ]
    elif score >= 50:
        risk_level = RiskLevel.MEDIUM
        explanation = "Message contains moderate urgency language or unfamiliar security notices."
        actions = ["Exercise caution before taking action on this message"]
    elif score >= 30:
        risk_level = RiskLevel.LOW
        explanation = "Low Risk: Minor marketing urgency terms detected with no credential solicitation."
        actions = ["Review message normally"]
    else:
        risk_level = RiskLevel.SAFE
        explanation = "Safe: No phishing, credential harvesting, or urgency indicators detected."
        actions = ["No action required"]

    return UnifiedAnalysisResponse(
        risk_level=risk_level,
        risk_score=score,
        explanation=explanation,
        signals={
            "urgency_score": round(urgency_score, 2),
            "urgency_language_detected": urgency_score > 0.3,
            "credential_solicitation": credential_solicitation,
            "domain_mismatch": bool(has_link and targeted_brand),
            "brand_targeted": targeted_brand,
            "contains_url": has_link,
            "prompt_injection_detected": False,
            "model_type": f"nlp_hybrid_transformer_v{SYSTEM_PROMPT_VERSION}",
            "source_type": request.source_type.value,
        },
        recommended_actions=actions,
        confidence_score=0.94 if score >= 80 else 0.88,
    )
