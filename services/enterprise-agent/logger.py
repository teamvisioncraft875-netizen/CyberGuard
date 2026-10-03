"""
CYBERGUARD Enterprise Agent — Structured Logger
Provides formatted console and file logging with automatic secret redaction.
"""

import os
import sys
import logging
import re
from typing import Any, Optional

# Patterns to mask in logs to ensure credential_secret and tokens are never leaked
SENSITIVE_PATTERNS = [
    re.compile(r'(credential_secret[\'"]?\s*[:=]\s*[\'"]?)([^\'"\s,}{]+)([\'"]?)', re.IGNORECASE),
    re.compile(r'(enrollment_token[\'"]?\s*[:=]\s*[\'"]?)([^\'"\s,}{]+)([\'"]?)', re.IGNORECASE),
    re.compile(r'(x-agent-credential-secret[\'"]?\s*[:=]\s*[\'"]?)([^\'"\s,}{]+)([\'"]?)', re.IGNORECASE),
    re.compile(r'(password[\'"]?\s*[:=]\s*[\'"]?)([^\'"\s,}{]+)([\'"]?)', re.IGNORECASE),
    re.compile(r'(bearer\s+)([a-zA-Z0-9_\-\.]+)', re.IGNORECASE),
]


def _mask_match(match: re.Match) -> str:
    groups = match.groups()
    if len(groups) == 3:
        return f"{groups[0]}[REDACTED]{groups[2]}"
    elif len(groups) == 2:
        return f"{groups[0]}[REDACTED]"
    elif len(groups) == 1:
        return "[REDACTED]"
    return match.group(0)


class RedactingFormatter(logging.Formatter):
    """Custom logging formatter that strips out secrets and sensitive tokens."""

    def __init__(self, fmt: Optional[str] = None, datefmt: Optional[str] = None):
        super().__init__(fmt=fmt, datefmt=datefmt)

    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        sanitized = original
        for pattern in SENSITIVE_PATTERNS:
            sanitized = pattern.sub(_mask_match, sanitized)
        return sanitized


def sanitize_text(text: Any) -> str:
    """Sanitize any arbitrary string or representation before logging."""
    s = str(text)
    for pattern in SENSITIVE_PATTERNS:
        s = pattern.sub(_mask_match, s)
    return s


def setup_logger(
    name: str = "enterprise_agent",
    log_level: str = "INFO",
    log_file: Optional[str] = None
) -> logging.Logger:
    """
    Configures and returns the agent logger.
    Outputs structured timestamps [YYYY-MM-DD HH:MM:SS] [LEVEL] message.
    """
    logger = logging.getLogger(name)
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    # Avoid duplicate handlers if setup_logger is called multiple times
    if logger.handlers:
        return logger

    log_format = "[%(asctime)s] [%(levelname)s] %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    formatter = RedactingFormatter(fmt=log_format, datefmt=date_format)

    # Console Handler (stdout)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(numeric_level)
    logger.addHandler(console_handler)

    # Optional File Handler
    if log_file:
        try:
            log_dir = os.path.dirname(os.path.abspath(log_file))
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(formatter)
            file_handler.setLevel(numeric_level)
            logger.addHandler(file_handler)
        except Exception as e:
            # Fallback gracefully if file cannot be created
            logger.warning(f"Could not initialize file logging to {log_file}: {e}")

    logger.propagate = False
    return logger


def get_logger(name: str = "enterprise_agent") -> logging.Logger:
    """Retrieves an existing logger or sets up default if uninitialized."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        return setup_logger(name)
    return logger
