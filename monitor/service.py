"""
Background monitoring service that periodically checks SQL Server health
and triggers alerts + AI analysis when thresholds are breached.
"""

import json
import logging
import threading
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from pathlib import Path
from typing import Optional

from diagnostics.connector import SQLServerConnector
from diagnostics.queries import DIAGNOSTIC_PROFILES, BLOCKING_CHAINS, PLE_CHECK, LONG_RUNNING_QUERIES
from analyzer.engine import AIAnalyzer

logger = logging.getLogger("dba-ai-assistant")


# ─────────────────────────────────────────────────────────────────────
# THRESHOLD-BASED CHECKS (fast, lightweight)
# ─────────────────────────────────────────────────────────────────────

THRESHOLD_CHECKS = {
    "blocking": {
        "query": BLOCKING_CHAINS,
        "condition": lambda result: result["row_count"] > 0,
        "severity": "CRITICAL",
        "message": "Active blocking detected — {row_count} sessions blocked",
        "escalation_profile": "blocking",
    },
    "ple_low": {
        "query": PLE_CHECK,
        "condition": lambda result: (
            result["row_count"] > 0
            and result["rows"][0].get("page_life_expectancy_sec", 9999) < 300
        ),
        "severity": "WARNING",
        "message": "Page Life Expectancy below 300s — memory pressure",
        "escalation_profile": "memory",
    },
    "long_queries": {
        "query": LONG_RUNNING_QUERIES,
        "condition": lambda result: result["row_count"] > 0,
        "severity": "WARNING",
        "message": "Long-running queries detected — {row_count} queries >5s",
        "escalation_profile": "slow_queries",
    },
}


class AlertManager:
    """Sends alerts via email, file, or webhook."""

    def __init__(self, config: dict):
        self.config = config
        self.report_dir = Path(config.get("report_dir", "reports"))
        self.report_dir.mkdir(exist_ok=True)

    def send_alert(self, subject: str, body: str, severity: str = "WARNING"):
        """Dispatch alert through configured channels."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Always save to file
        report_path = self.report_dir / f"alert_{timestamp}_{severity}.md"
        report_path.write_text(f"# {subject}\n\n{body}", encoding="utf-8")
        logger.info(f"Alert saved to {report_path}")

        # Email if configured
        email_cfg = self.config.get("email")
        if email_cfg and email_cfg.get("enabled"):
            self._send_email(subject, body, email_cfg)

        # Webhook if configured
        webhook_url = self.config.get("webhook_url")
        if webhook_url:
            self._send_webhook(subject, body, severity, webhook_url)

    def _send_email(self, subject: str, body: str, email_cfg: dict):
        """Send alert via SMTP email."""
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[DBA-AI-{subject}]"
            msg["From"] = email_cfg["from_addr"]
            msg["To"] = ", ".join(email_cfg["to_addrs"])
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(email_cfg["smtp_server"], email_cfg.get("smtp_port", 587)) as server:
                if email_cfg.get("use_tls", True):
                    server.starttls()
                if email_cfg.get("smtp_user"):
                    server.login(email_cfg["smtp_user"], email_cfg["smtp_password"])
                server.sendmail(email_cfg["from_addr"], email_cfg["to_addrs"], msg.as_string())
            logger.info("Alert email sent")
        except Exception as e:
            logger.error(f"Email send failed: {e}")

    def _send_webhook(self, subject: str, body: str, severity: str, url: str):
        """Send alert to a webhook (Teams, Slack, etc.)."""
        try:
            import urllib.request
            payload = json.dumps({
                "title": subject,
                "text": body[:2000],
                "severity": severity,
                "timestamp": datetime.now().isoformat(),
            }).encode("utf-8")
            req = urllib.request.Request(
                url, data=payload,
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=10)
            logger.info("Webhook alert sent")
        except Exception as e:
            logger.error(f"Webhook send failed: {e}")


class MonitorService:
    """
    Background service that periodically runs threshold checks.
    When a threshold is breached, it escalates to a full diagnostic
    profile + AI analysis and sends alerts.
    """

    def __init__(self, connector: SQLServerConnector,
                 analyzer: AIAnalyzer,
                 alert_manager: AlertManager,
                 check_interval: int = 60,
                 cooldown: int = 300):
        self.connector = connector
        self.analyzer = analyzer
        self.alert_manager = alert_manager
        self.check_interval = check_interval  # seconds between checks
        self.cooldown = cooldown  # seconds before re-alerting same issue
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_alerts: dict = {}  # check_name -> last_alert_timestamp

    def start(self):
        """Start the monitoring loop in a background thread."""
        if self._thread and self._thread.is_alive():
            logger.warning("Monitor already running")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info(
            f"Monitor started — checking every {self.check_interval}s, "
            f"cooldown {self.cooldown}s"
        )

    def stop(self):
        """Stop the monitoring loop."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("Monitor stopped")

    def _run_loop(self):
        """Main monitoring loop."""
        while not self._stop_event.is_set():
            try:
                self._run_checks()
            except Exception as e:
                logger.error(f"Monitor check error: {e}")
            self._stop_event.wait(self.check_interval)

    def _run_checks(self):
        """Run all threshold checks."""
        for check_name, check in THRESHOLD_CHECKS.items():
            try:
                result = self.connector.execute_query(check["query"])
                if result.get("error"):
                    logger.warning(f"Check {check_name} error: {result['error']}")
                    continue

                if check["condition"](result):
                    # Check cooldown
                    now = time.time()
                    last_alert = self._last_alerts.get(check_name, 0)
                    if now - last_alert < self.cooldown:
                        logger.debug(f"Check {check_name} in cooldown, skipping alert")
                        continue

                    self._last_alerts[check_name] = now
                    message = check["message"].format(row_count=result["row_count"])
                    logger.warning(f"THRESHOLD BREACHED: {check_name} — {message}")

                    # Escalate: run full diagnostic profile + AI analysis
                    profile = DIAGNOSTIC_PROFILES.get(check["escalation_profile"])
                    if profile:
                        diag_results = self.connector.run_diagnostic_profile(profile)
                        analysis = self.analyzer.analyze(
                            diag_results,
                            context=f"Auto-detected: {message}",
                            profile_name=check["escalation_profile"],
                        )
                    else:
                        analysis = f"Threshold breached: {message}\n\nRaw data:\n```json\n{json.dumps(result['rows'][:10], indent=2, default=str)}\n```"

                    self.alert_manager.send_alert(
                        subject=f"{check['severity']}: {message}",
                        body=analysis,
                        severity=check["severity"],
                    )

            except Exception as e:
                logger.error(f"Check {check_name} failed: {e}")

    def run_single_check(self) -> list:
        """Run all checks once (for manual/CLI triggering). Returns list of alerts."""
        alerts = []
        for check_name, check in THRESHOLD_CHECKS.items():
            result = self.connector.execute_query(check["query"])
            if result.get("error"):
                continue
            if check["condition"](result):
                message = check["message"].format(row_count=result["row_count"])
                alerts.append({
                    "check": check_name,
                    "severity": check["severity"],
                    "message": message,
                    "row_count": result["row_count"],
                })
        return alerts
