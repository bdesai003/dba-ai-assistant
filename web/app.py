"""
Flask web dashboard for the DBA AI Assistant.
Provides a browser-based UI for triggering diagnostics and viewing reports.
"""

import json
import logging
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, request, jsonify

from diagnostics.connector import SQLServerConnector
from diagnostics.queries import DIAGNOSTIC_PROFILES
from analyzer.engine import AIAnalyzer
from analyzer.token_resolver import resolve_api_key
from analyzer.session_store import ChatSessionStore
from monitor.service import MonitorService, AlertManager

logger = logging.getLogger("dba-ai-assistant")

# Module-level references (set by create_app)
_connector = None
_analyzer = None
_monitor = None
_config = None
_chat_sessions = None


def create_app(config: dict) -> Flask:
    """Create and configure the Flask application."""
    global _connector, _analyzer, _monitor, _config, _chat_sessions
    _config = config
    _chat_sessions = ChatSessionStore()

    app = Flask(__name__, template_folder="../templates")
    app.secret_key = config.get("web", {}).get("secret_key", "change-me-in-production")

    db = config["sql_server"]
    _connector = SQLServerConnector(
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

    ai = config.get("ai", {})
    api_key = resolve_api_key(ai.get("provider", "rules"), ai.get("api_key"))
    _analyzer = AIAnalyzer(
        provider=ai.get("provider", "rules"),
        api_key=api_key,
        api_base=ai.get("api_base"),
        model=ai.get("model", "gpt-4o"),
        extra_headers=ai.get("extra_headers"),
    )

    alert_cfg = config.get("alerts", {})
    alert_manager = AlertManager(alert_cfg)
    _monitor = MonitorService(
        connector=_connector,
        analyzer=_analyzer,
        alert_manager=alert_manager,
    )

    register_routes(app)
    return app


def register_routes(app: Flask):
    """Register all web routes."""

    @app.route("/")
    def index():
        return render_template("index.html",
                               profiles=DIAGNOSTIC_PROFILES,
                               server=_config["sql_server"]["server"],
                               connected_as=_connector.auth_description())

    @app.route("/api/test-connection", methods=["POST"])
    def api_test_connection():
        result = _connector.test_connection()
        return jsonify(result)

    @app.route("/api/diagnose", methods=["POST"])
    def api_diagnose():
        data = request.get_json() or {}
        profile_name = data.get("profile", "quick_health")
        context = data.get("context", "")

        if profile_name not in DIAGNOSTIC_PROFILES:
            return jsonify({"error": f"Unknown profile: {profile_name}"}), 400

        profile = DIAGNOSTIC_PROFILES[profile_name]

        # Run diagnostics
        results = _connector.run_diagnostic_profile(profile)

        # Build summary of raw results
        summary = {}
        for name, result in results.items():
            summary[name] = {
                "row_count": result["row_count"],
                "error": result.get("error"),
            }

        # AI analysis
        analysis = _analyzer.analyze(results, context=context, profile_name=profile_name)

        # Save report
        report_dir = Path(_config.get("alerts", {}).get("report_dir", "reports"))
        report_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = report_dir / f"diag_{profile_name}_{timestamp}.md"
        ai_cfg = _config.get("ai", {})
        api_endpoint = _analyzer.last_api_endpoint or ai_cfg.get("provider", "rules")
        header = (
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  "
            f"**Provider:** {ai_cfg.get('provider', 'rules')} | "
            f"**Model:** {ai_cfg.get('model', 'N/A')} | "
            f"**API Endpoint:** {api_endpoint}\n\n---\n\n"
        )
        report_path.write_text(header + analysis, encoding="utf-8")

        return jsonify({
            "profile": profile_name,
            "summary": summary,
            "analysis": analysis,
            "api_endpoint": api_endpoint,
            "timestamp": datetime.now().isoformat(),
            "report_file": str(report_path),
        })

    @app.route("/api/check", methods=["POST"])
    def api_check():
        alerts = _monitor.run_single_check()
        return jsonify({"alerts": alerts, "timestamp": datetime.now().isoformat()})

    @app.route("/api/reports", methods=["GET"])
    def api_reports():
        report_dir = Path(_config.get("alerts", {}).get("report_dir", "reports"))
        if not report_dir.exists():
            return jsonify({"reports": []})
        reports = sorted(report_dir.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
        return jsonify({
            "reports": [
                {"name": r.name, "size_kb": round(r.stat().st_size / 1024, 1),
                 "modified": datetime.fromtimestamp(r.stat().st_mtime).isoformat()}
                for r in reports[:50]
            ]
        })

    @app.route("/api/reports/<filename>", methods=["GET"])
    def api_report_detail(filename: str):
        report_dir = Path(_config.get("alerts", {}).get("report_dir", "reports"))
        # Prevent path traversal
        safe_name = Path(filename).name
        report_path = report_dir / safe_name
        if not report_path.exists() or not report_path.is_file():
            return jsonify({"error": "Report not found"}), 404
        return jsonify({"name": safe_name, "content": report_path.read_text(encoding="utf-8")})

    @app.route("/api/investigate", methods=["POST"])
    def api_investigate():
        from analyzer.agent import DBAAgent

        data = request.get_json() or {}
        problem = data.get("problem", "").strip()
        if not problem:
            return jsonify({"error": "No problem description provided"}), 400

        ai = _config.get("ai", {})
        provider = ai.get("provider", "rules")
        api_key = resolve_api_key(provider, ai.get("api_key"))
        agent = DBAAgent(
            connector=_connector,
            provider=provider,
            api_key=api_key,
            api_base=ai.get("api_base"),
            model=ai.get("model", "gpt-4o"),
            api_version=ai.get("api_version", "2024-06-01"),
            extra_headers=ai.get("extra_headers"),
        )

        steps = []
        def on_progress(msg, data=None):
            steps.append(msg)

        result = agent.start_session(problem, on_progress=on_progress)
        report = agent.format_investigation_result(problem, result)

        # Persist conversation state so follow-up chat questions can resume it
        session_id = _chat_sessions.create(problem, agent.provider, agent.model)
        _chat_sessions.update(
            session_id,
            messages=result["messages"],
            investigation_log=result["investigation_log"],
            use_tools=result["use_tools"],
        )
        _chat_sessions.append_history(session_id, "user", problem)
        _chat_sessions.append_history(session_id, "assistant", report)

        # Save report
        report_dir = Path(_config.get("alerts", {}).get("report_dir", "reports"))
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

        return jsonify({
            "report": report,
            "steps": steps,
            "api_endpoint": api_endpoint,
            "timestamp": datetime.now().isoformat(),
            "report_file": str(report_path),
            "session_id": session_id,
        })

    @app.route("/api/chat", methods=["POST"])
    def api_chat():
        """Continue an investigation session with a follow-up chat question
        (tuning ideas, execution plan analysis, etc.)."""
        from analyzer.agent import DBAAgent

        data = request.get_json() or {}
        session_id = data.get("session_id", "").strip()
        message = data.get("message", "").strip()
        if not session_id:
            return jsonify({"error": "No session_id provided"}), 400
        if not message:
            return jsonify({"error": "No message provided"}), 400

        session = _chat_sessions.get(session_id)
        if not session:
            return jsonify({"error": "Session not found or expired"}), 404

        ai = _config.get("ai", {})
        provider = session.get("provider", ai.get("provider", "rules"))
        api_key = resolve_api_key(provider, ai.get("api_key"))
        agent = DBAAgent(
            connector=_connector,
            provider=provider,
            api_key=api_key,
            api_base=ai.get("api_base"),
            model=session.get("model", ai.get("model", "gpt-4o")),
            api_version=ai.get("api_version", "2024-06-01"),
            extra_headers=ai.get("extra_headers"),
        )

        steps = []
        def on_progress(msg, data=None):
            steps.append(msg)

        result = agent.continue_session(
            session["messages"], session["investigation_log"], message,
            on_progress=on_progress, use_tools=session.get("use_tools", True),
        )
        answer = agent.format_chat_answer(message, result)

        _chat_sessions.update(
            session_id,
            messages=result["messages"],
            investigation_log=result["investigation_log"],
            use_tools=result["use_tools"],
        )
        _chat_sessions.append_history(session_id, "user", message)
        _chat_sessions.append_history(session_id, "assistant", answer)

        return jsonify({
            "answer": answer,
            "steps": steps,
            "done": result["done"],
            "session_id": session_id,
            "timestamp": datetime.now().isoformat(),
        })

    @app.route("/api/chat/<session_id>", methods=["GET"])
    def api_chat_history(session_id: str):
        """Return the display transcript for a chat session (for reloading the UI)."""
        session = _chat_sessions.get(session_id)
        if not session:
            return jsonify({"error": "Session not found or expired"}), 404
        return jsonify({
            "session_id": session_id,
            "problem": session["problem"],
            "history": session["history"],
            "created_at": datetime.fromtimestamp(session["created_at"]).isoformat(),
            "last_active": datetime.fromtimestamp(session["last_active"]).isoformat(),
        })

    @app.route("/api/chat/<session_id>", methods=["DELETE"])
    def api_chat_delete(session_id: str):
        """Discard a chat session's conversation memory."""
        _chat_sessions.delete(session_id)
        return jsonify({"deleted": session_id})
