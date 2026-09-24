"""
Centralized Security, Secret-Handling, and Redaction Module for HHGOA Fraud System.
Ensures no credentials, tokens, secrets, or authorization headers leak into
logs, diagnostics, exceptions, generated reports, or API responses.
"""

import re
import logging
from typing import Any, Dict, Optional
import backend.config as cfg

logger = logging.getLogger("security")

# Compiled regex patterns for credential detection
JWT_PATTERN = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}")
BEARER_PATTERN = re.compile(r"(?i)(bearer\s+)[a-zA-Z0-9_.-]+")
BASIC_AUTH_PATTERN = re.compile(r"(?i)(basic\s+)[a-zA-Z0-9+/=]+")
AUTH_HEADER_PATTERN = re.compile(r"(?i)(authorization:\s*)([^\r\n]+)")
URL_SECRET_PATTERN = re.compile(r"(?i)(secret|password|token)=([^&\"'\s]+)")
JSON_SECRET_PATTERN = re.compile(r'(?i)("(?:secret|password|token|api_token)"\s*:\s*)"[^"]+"')

def get_known_secrets() -> list[str]:
    """Retrieves all non-empty sensitive values currently loaded in config."""
    secrets = []
    for val in [cfg.TG_SECRET, cfg.TG_PASSWORD, cfg.TG_API_TOKEN]:
        if val and isinstance(val, str) and len(val.strip()) > 3:
            secrets.append(val.strip())
    return secrets

def redact_sensitive_text(text: Any) -> str:
    """
    Scans input text for sensitive credentials (configured secrets, JWTs,
    Bearer tokens, Basic Auth credentials, query params) and replaces them
    with [REDACTED].
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)

    # 1. Redact explicit configured secrets
    for secret in get_known_secrets():
        text = text.replace(secret, "[REDACTED]")

    # 2. Redact JWT tokens
    text = JWT_PATTERN.sub("[REDACTED]", text)

    # 3. Redact Bearer and Basic headers
    text = BEARER_PATTERN.sub(r"\1[REDACTED]", text)
    text = BASIC_AUTH_PATTERN.sub(r"\1[REDACTED]", text)

    # 4. Redact raw Authorization headers
    text = AUTH_HEADER_PATTERN.sub(r"\1[REDACTED]", text)

    # 5. Redact URL query parameters containing credentials
    text = URL_SECRET_PATTERN.sub(r"\1=[REDACTED]", text)

    # 6. Redact JSON key-value pairs
    text = JSON_SECRET_PATTERN.sub(r'\1"[REDACTED]"', text)

    return text

def sanitize_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
    """Returns a sanitized copy of HTTP headers with credentials redacted."""
    sanitized = {}
    for k, v in headers.items():
        if k.lower() in ["authorization", "x-auth-token", "cookie"]:
            sanitized[k] = "[REDACTED]"
        else:
            sanitized[k] = redact_sensitive_text(str(v))
    return sanitized

def sanitize_exception(e: Exception) -> str:
    """Returns a sanitized string representation of an exception."""
    return redact_sensitive_text(str(e))

def safe_diagnostic_summary() -> Dict[str, Any]:
    """
    Returns a safe diagnostic dictionary indicating whether credentials
    are configured without revealing any sensitive values.
    """
    return {
        "TG_HOST": cfg.TG_HOST,
        "TG_GRAPH": cfg.TG_GRAPH,
        "TG_USERNAME": cfg.TG_USERNAME,
        "TG_SECRET": "[CONFIGURED]" if cfg.TG_SECRET else "[NOT CONFIGURED]",
        "TG_PASSWORD": "[CONFIGURED]" if cfg.TG_PASSWORD else "[NOT CONFIGURED]",
        "TG_API_TOKEN": "[CONFIGURED]" if cfg.TG_API_TOKEN else "[NOT CONFIGURED]",
        "STRICT_TIGERGRAPH_REQUIRED": cfg.STRICT_TG_REQUIRED
    }

class RedactingFilter(logging.Filter):
    """Logging filter that ensures log records never contain sensitive credentials."""
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_sensitive_text(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: redact_sensitive_text(v) if isinstance(v, str) else v for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(redact_sensitive_text(v) if isinstance(v, str) else v for v in record.args)
        return True

def apply_global_redaction_logging():
    """Attaches RedactingFilter to the root logger and all active loggers."""
    root = logging.getLogger()
    flt = RedactingFilter()
    root.addFilter(flt)
    for handler in root.handlers:
        handler.addFilter(flt)

# Automatically apply redaction filter upon import
apply_global_redaction_logging()
