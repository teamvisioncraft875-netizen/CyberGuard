"""
CYBERGUARD ML Service Prompts Package
"""
from app.prompts.phishing import (
    SYSTEM_PROMPT_VERSION,
    LLM_MAX_TOKENS,
    PHISHING_SYSTEM_PROMPT,
    sanitize_message_input,
)

__all__ = [
    "SYSTEM_PROMPT_VERSION",
    "LLM_MAX_TOKENS",
    "PHISHING_SYSTEM_PROMPT",
    "sanitize_message_input",
]
