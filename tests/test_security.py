#!/usr/bin/env python3
"""
Security, Secret-Handling, and Repository Hygiene Test Suite.
Validates that:
1. Real secrets are never returned by diagnostics.
2. Logs contain [REDACTED] instead of secret values.
3. API error responses and exceptions do not leak Authorization headers or tokens.
4. .env is ignored by Git.
5. .env.example contains placeholders only.
6. Progress reports and documentation contain no credential values.
7. TigerGraph health checks work using environment variables.
8. Local fallback never masks a failed live connection when strict mode is active.
"""

import os
import sys
import unittest
import logging
import io
from pathlib import Path

# Add project root
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import backend.config as cfg
from backend.security import (
    redact_sensitive_text,
    safe_diagnostic_summary,
    sanitize_headers,
    sanitize_exception,
    RedactingFilter,
    get_known_secrets
)
from backend.tigergraph.client import TigerGraphClient
from backend.tigergraph.gateway import graph_gateway

class TestSecurityAndHygiene(unittest.TestCase):

    def test_01_diagnostics_never_leak_secrets(self):
        """Verify safe diagnostics return status tags ([CONFIGURED]) and never real secrets."""
        diag = safe_diagnostic_summary()
        self.assertIn("TG_SECRET", diag)
        self.assertIn("TG_PASSWORD", diag)
        self.assertIn("TG_API_TOKEN", diag)
        
        # Must be status tags, never actual secret strings
        for k in ["TG_SECRET", "TG_PASSWORD", "TG_API_TOKEN"]:
            self.assertIn(diag[k], ["[CONFIGURED]", "[NOT CONFIGURED]"])
            if cfg.TG_SECRET:
                self.assertNotEqual(diag[k], cfg.TG_SECRET)

        cfg_view = cfg.get_safe_config()
        for k in ["TG_SECRET", "TG_PASSWORD", "TG_API_TOKEN"]:
            self.assertIn(cfg_view[k], ["[CONFIGURED]", "[NOT CONFIGURED]"])

    def test_02_logging_redacts_secrets(self):
        """Verify logger records automatically redact sensitive credentials."""
        log_stream = io.StringIO()
        handler = logging.StreamHandler(log_stream)
        handler.addFilter(RedactingFilter())
        
        test_logger = logging.getLogger("test_sec_logger")
        test_logger.setLevel(logging.INFO)
        test_logger.addHandler(handler)

        fake_secret = "super_secret_sample_key_12345"
        # Temporarily mock fake secret into known secrets
        old_secret = cfg.TG_SECRET
        cfg.TG_SECRET = fake_secret
        try:
            test_logger.info(f"Connecting with secret: {fake_secret}")
            test_logger.info("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3j")
            
            output = log_stream.getvalue()
            self.assertNotIn(fake_secret, output)
            self.assertIn("[REDACTED]", output)
        finally:
            cfg.TG_SECRET = old_secret
            test_logger.removeHandler(handler)

    def test_03_headers_and_exceptions_redacted(self):
        """Verify headers and exception messages do not leak Authorization tokens."""
        raw_headers = {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.sample_payload.sample_sig",
            "Content-Type": "application/json"
        }
        clean = sanitize_headers(raw_headers)
        self.assertEqual(clean["Authorization"], "[REDACTED]")
        self.assertEqual(clean["Content-Type"], "application/json")

        exc = ValueError("HTTP 401 Unauthorized for secret=my_db_secret_val with Authorization: Bearer token123")
        clean_exc = sanitize_exception(exc)
        self.assertNotIn("token123", clean_exc)
        self.assertIn("[REDACTED]", clean_exc)

    def test_04_gitignore_rules(self):
        """Verify .gitignore exists and strictly ignores .env and .env.* files."""
        gitignore_path = BASE_DIR / ".gitignore"
        self.assertTrue(gitignore_path.exists(), ".gitignore must exist")
        
        content = gitignore_path.read_text(encoding="utf-8").splitlines()
        rules = [line.strip() for line in content if line.strip() and not line.startswith("#")]
        
        self.assertIn(".env", rules)
        self.assertIn(".env.*", rules)
        self.assertIn("!.env.example", rules)

    def test_05_env_example_has_placeholders_only(self):
        """Verify .env.example contains placeholders only and no real credentials."""
        example_path = BASE_DIR / ".env.example"
        self.assertTrue(example_path.exists(), ".env.example must exist")
        
        content = example_path.read_text(encoding="utf-8")
        self.assertIn("<DATABASE_SECRET>", content)
        self.assertIn("<DATABASE_PASSWORD>", content)
        self.assertIn("<DATABASE_API_TOKEN>", content)
        
        # Ensure known active secrets are NOT in .env.example
        for s in get_known_secrets():
            self.assertNotIn(s, content)

    def test_06_reports_contain_no_credentials(self):
        """Verify markdown reports, HTML files, and generated docs contain no credentials."""
        active_secrets = get_known_secrets()
        if not active_secrets:
            self.skipTest("No active secrets to test against reports")

        report_files = [
            BASE_DIR / "TigerGraph_Fraud_Investigation_Report.html",
            Path(r"C:\Users\afnan\.gemini\antigravity\brain\f2d61920-de01-4273-93d3-81bc68517149\project_progress_report.md")
        ]

        for rf in report_files:
            if rf.exists():
                text = rf.read_text(encoding="utf-8", errors="ignore")
                for s in active_secrets:
                    self.assertNotIn(s, text, f"Secret leaked in {rf.name}")
                self.assertIn("[CONFIGURED]", text, f"Expected [CONFIGURED] in {rf.name}")

    def test_07_health_check_works_via_env(self):
        """Verify TigerGraph client connects using environment variables."""
        client = TigerGraphClient()
        health = client.check_health()
        self.assertIn("mode", health)
        self.assertIn("status", health)
        self.assertIn("host", health)
        
        # Health output must not contain secrets
        for s in get_known_secrets():
            self.assertNotIn(s, str(health))

    def test_08_strict_mode_prevents_silent_fallback(self):
        """Verify that when strict mode is required, unconfigured or unreachable host fails explicitly."""
        # Create client with invalid unreachable host
        fake_client = TigerGraphClient(host="https://invalid-unreachable-host.nonexistent.tgcloud.io")
        old_strict = cfg.STRICT_TG_REQUIRED
        try:
            cfg.STRICT_TG_REQUIRED = True
            h = fake_client.check_health()
            self.assertEqual(h["mode"], "CONNECTION_FAILED", "Strict mode must NOT return LOCAL_FALLBACK on failure")
            self.assertIn("unreachable", h["status"])
        finally:
            cfg.STRICT_TG_REQUIRED = old_strict

if __name__ == "__main__":
    unittest.main()
