"""
DBA AI Assistant — Command-Line Interface

Usage:
  python cli.py diagnose [--profile PROFILE] [--context "user complaint"]
  python cli.py monitor  [--interval 60] [--cooldown 300]
  python cli.py check    (one-shot threshold check)
  python cli.py test     (test SQL Server connectivity)
  python cli.py profiles (list available diagnostic profiles)
  python cli.py web      (start web dashboard)
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import yaml

from diagnostics.connector import SQLServerConnector
from diagnostics.queries import DIAGNOSTIC_PROFILES
from analyzer.engine import AIAnalyzer
from analyzer.agent import DBAAgent
from analyzer.token_resolver import resolve_api_key
from monitor.service import MonitorService, AlertManager


def load_config(path: str = "config.yaml") -> dict:
    """Load configuration from YAML file."""
    config_path = Path(path)
    if not config_path.exists():
        print(f"Config file not found: {path}")
        print("Run: copy config.example.yaml config.yaml   and edit it.")
        sys.exit(1)
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def build_connector(config: dict) -> SQLServerConnector:
    """Build SQLServerConnector from config."""
    db = config["sql_server"]
    return SQLServerConnector(
        server=db["server"],
        database=db.get("database", "master"),
        username=db.get("username"),
        password=db.get("password"),
        driver=db.get("driver", "{ODBC Driver 17 for SQL Server}"),
        trusted_connection=db.get("trusted_connection", False),
        connect_timeout=db.get("connect_timeout", 10),
        query_timeout=db.get("query_timeout", 30),
        encrypt=db.get("encrypt", True),
        trust_server_certificate=db.get("trust_server_certificate", False),
    )


def build_analyzer(config: dict) -> AIAnalyzer:
    """Build AIAnalyzer from config."""
    ai = config.get("ai", {})
    api_key = resolve_api_key(ai.get("provider", "rules"), ai.get("api_key"))
    return AIAnalyzer(
        provider=ai.get("provider", "rules"),
        api_key=api_key,
        api_base=ai.get("api_base"),
        model=ai.get("model", "gpt-4o"),
        api_version=ai.get("api_version", "2024-06-01"),
        extra_headers=ai.get("extra_headers"),
    )


def setup_logging(level: str = "INFO"):
    """Configure logging."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# ─────────────────────────────────────────────────────────────────────
# CLI COMMANDS
# ─────────────────────────────────────────────────────────────────────

def cmd_diagnose(args, config):
    """Run a diagnostic profile and produce AI analysis."""
    connector = build_connector(config)
    analyzer = build_analyzer(config)

    profile_name = args.profile or "quick_health"
    if profile_name not in DIAGNOSTIC_PROFILES:
        print(f"Unknown profile '{profile_name}'. Available: {', '.join(DIAGNOSTIC_PROFILES.keys())}")
        sys.exit(1)

    profile = DIAGNOSTIC_PROFILES[profile_name]
    print(f"\n{'='*60}")
    print(f"  DBA AI Assistant — Diagnostic: {profile_name}")
    print(f"  {profile['description']}")
    print(f"  Server: {config['sql_server']['server']}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    print("Collecting diagnostics...")
    results = connector.run_diagnostic_profile(profile)

    # Show raw result counts
    for name, result in results.items():
        status = "✓" if not result.get("error") else "✗"
        count = result.get("row_count", 0)
        label = name.replace("_", " ").title()
        err = f" — ERROR: {result['error']}" if result.get("error") else ""
        print(f"  {status} {label}: {count} rows{err}")

    print("\nAnalyzing results...\n")
    context = args.context or ""
    report = analyzer.analyze(results, context=context, profile_name=profile_name)

    print(report)

    # Save report
    report_dir = Path(config.get("alerts", {}).get("report_dir", "reports"))
    report_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = report_dir / f"diag_{profile_name}_{timestamp}.md"
    ai_cfg = config.get("ai", {})
    api_endpoint = analyzer.last_api_endpoint or ai_cfg.get("provider", "rules")
    header = (
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  "
        f"**Provider:** {ai_cfg.get('provider', 'rules')} | "
        f"**Model:** {ai_cfg.get('model', 'N/A')} | "
        f"**API Endpoint:** {api_endpoint}\n\n---\n\n"
    )
    report_path.write_text(header + report, encoding="utf-8")
    print(f"\n📄 Report saved: {report_path}")


def cmd_monitor(args, config):
    """Start background monitoring service."""
    connector = build_connector(config)
    analyzer = build_analyzer(config)
    alert_cfg = config.get("alerts", {})
    alert_manager = AlertManager(alert_cfg)

    interval = args.interval or config.get("monitor", {}).get("check_interval", 60)
    cooldown = args.cooldown or config.get("monitor", {}).get("cooldown", 300)

    service = MonitorService(
        connector=connector,
        analyzer=analyzer,
        alert_manager=alert_manager,
        check_interval=interval,
        cooldown=cooldown,
    )

    print(f"\n{'='*60}")
    print(f"  DBA AI Monitor — Watching {config['sql_server']['server']}")
    print(f"  Check interval: {interval}s | Cooldown: {cooldown}s")
    print(f"  Reports saved to: {alert_cfg.get('report_dir', 'reports')}/")
    print(f"  Press Ctrl+C to stop")
    print(f"{'='*60}\n")

    service.start()
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        service.stop()
        print("Monitor stopped.")


def cmd_check(args, config):
    """One-shot threshold check."""
    connector = build_connector(config)
    analyzer = build_analyzer(config)
    alert_cfg = config.get("alerts", {})
    alert_manager = AlertManager(alert_cfg)

    service = MonitorService(
        connector=connector,
        analyzer=analyzer,
        alert_manager=alert_manager,
    )

    print(f"Running threshold checks against {config['sql_server']['server']}...\n")
    alerts = service.run_single_check()

    if not alerts:
        print("🟢 All checks passed — no issues detected.")
    else:
        for alert in alerts:
            icon = "🔴" if alert["severity"] == "CRITICAL" else "🟡"
            print(f"{icon} [{alert['severity']}] {alert['message']}")
        print(f"\nRun 'python cli.py diagnose' for full analysis.")


def cmd_test(args, config):
    """Test SQL Server connectivity."""
    connector = build_connector(config)
    print(f"Testing connection to {config['sql_server']['server']}...")
    result = connector.test_connection()
    if result.get("error"):
        print(f"✗ Connection FAILED: {result['error']}")
        sys.exit(1)
    row = result["rows"][0] if result["rows"] else {}
    print(f"✓ Connected successfully!")
    print(f"  Server:   {row.get('server_name', '?')}")
    print(f"  Version:  {str(row.get('version', '?'))[:80]}")
    print(f"  Database: {row.get('current_db', '?')}")
    print(f"  Time:     {row.get('server_time', '?')}")


def cmd_profiles(args, config):
    """List available diagnostic profiles."""
    print(f"\n{'='*60}")
    print("  Available Diagnostic Profiles")
    print(f"{'='*60}\n")
    for name, profile in DIAGNOSTIC_PROFILES.items():
        queries = ", ".join(profile["queries"].keys())
        print(f"  {name:15s}  {profile['description']}")
        print(f"  {'':15s}  Queries: {queries}\n")


def cmd_web(args, config):
    """Start web dashboard."""
    from web.app import create_app
    app = create_app(config)
    host = config.get("web", {}).get("host", "127.0.0.1")
    port = config.get("web", {}).get("port", 5555)
    print(f"\n  Starting DBA AI Dashboard at http://{host}:{port}")
    print(f"  Press Ctrl+C to stop\n")
    app.run(host=host, port=port, debug=False)


def cmd_investigate(args, config):
    """Investigate a database issue using AI agent."""
    connector = build_connector(config)
    ai = config.get("ai", {})

    api_key = resolve_api_key(ai.get("provider", "rules"), ai.get("api_key"))
    agent = DBAAgent(
        connector=connector,
        provider=ai.get("provider", "rules"),
        api_key=api_key,
        api_base=ai.get("api_base"),
        model=ai.get("model", "gpt-4o"),
        api_version=ai.get("api_version", "2024-06-01"),
        max_iterations=args.max_steps,
        extra_headers=ai.get("extra_headers"),
    )

    problem = args.problem

    print(f"\n{'='*60}")
    print(f"  DBA AI Assistant — Investigation Mode")
    print(f"  Server: {config['sql_server']['server']}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")
    print(f"\nProblem: {problem}\n")

    def on_progress(msg, data=None):
        print(f"  {msg}")

    report = agent.investigate(problem, on_progress=on_progress)

    print(f"\n{'='*60}")
    print(f"  INVESTIGATION REPORT")
    print(f"{'='*60}\n")
    print(report)

    # Save report
    report_dir = Path(config.get("alerts", {}).get("report_dir", "reports"))
    report_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = report_dir / f"investigation_{timestamp}.md"
    api_endpoint = agent.last_api_endpoint or agent.provider
    header = (
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  "
        f"**Provider:** {agent.provider} | "
        f"**Model:** {agent.model} | "
        f"**API Endpoint:** {api_endpoint}\n\n---\n\n"
    )
    report_path.write_text(header + report, encoding="utf-8")
    print(f"\n📄 Report saved: {report_path}")


# ─────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="DBA AI Assistant — SQL Server Performance Diagnostics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py test
  python cli.py diagnose --profile quick_health
  python cli.py diagnose --profile blocking --context "Users reporting timeouts"
  python cli.py diagnose --profile full --context "Nightly ETL running slow"
  python cli.py investigate "Database is slow since 2pm"
  python cli.py investigate "Give me index recommendations for MyDB"
  python cli.py check
  python cli.py monitor --interval 60
  python cli.py profiles
  python cli.py web
        """,
    )
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--log-level", default="INFO", help="Logging level")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # diagnose
    p_diag = subparsers.add_parser("diagnose", help="Run diagnostic profile + AI analysis")
    p_diag.add_argument("--profile", "-p", default="quick_health",
                        help="Diagnostic profile (default: quick_health)")
    p_diag.add_argument("--context", "-c", default="",
                        help="Describe the issue (e.g., 'users report slowness')")

    # monitor
    p_mon = subparsers.add_parser("monitor", help="Start background monitoring")
    p_mon.add_argument("--interval", "-i", type=int, help="Check interval in seconds")
    p_mon.add_argument("--cooldown", type=int, help="Alert cooldown in seconds")

    # check
    subparsers.add_parser("check", help="One-shot threshold check")

    # test
    subparsers.add_parser("test", help="Test SQL Server connectivity")

    # profiles
    subparsers.add_parser("profiles", help="List diagnostic profiles")

    # web
    subparsers.add_parser("web", help="Start web dashboard")

    # investigate
    p_inv = subparsers.add_parser("investigate", help="AI-driven investigation of a problem")
    p_inv.add_argument("problem", help="Describe the issue in natural language")
    p_inv.add_argument("--max-steps", type=int, default=15,
                       help="Max investigation steps (default: 15)")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    setup_logging(args.log_level)
    config = load_config(args.config)

    commands = {
        "diagnose": cmd_diagnose,
        "monitor": cmd_monitor,
        "check": cmd_check,
        "test": cmd_test,
        "profiles": cmd_profiles,
        "web": cmd_web,
        "investigate": cmd_investigate,
    }
    commands[args.command](args, config)


if __name__ == "__main__":
    main()
