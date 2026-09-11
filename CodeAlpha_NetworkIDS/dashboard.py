"""Local visualization dashboard for NIDS alerts."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from flask import Flask, jsonify, render_template

from responder import load_alerts


def create_app(log_dir: Path) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    jsonl_path = log_dir / "alerts.jsonl"
    blocklist_path = log_dir / "blocklist.txt"

    @app.get("/")
    def index():
        return render_template("dashboard.html")

    @app.get("/api/alerts")
    def api_alerts():
        alerts = load_alerts(jsonl_path)
        return jsonify(list(reversed(alerts[-400:])))

    @app.get("/api/stats")
    def api_stats():
        alerts = load_alerts(jsonl_path)
        severity = Counter(row.get("severity", "MEDIUM") for row in alerts)
        classtype = Counter(row.get("classtype", "unknown") for row in alerts)
        sources = Counter(row.get("src_ip", "?") for row in alerts)
        blocked = []
        if blocklist_path.exists():
            blocked = [
                line.strip()
                for line in blocklist_path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")
            ]
        timeline = Counter(row.get("timestamp", "")[:16] for row in alerts)
        return jsonify(
            {
                "total": len(alerts),
                "blocked": blocked,
                "severity": dict(severity),
                "classtype": dict(classtype),
                "top_sources": sources.most_common(8),
                "timeline": sorted(timeline.items()),
            }
        )

    return app


def run_dashboard(log_dir: Path, port: int = 5050) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    app = create_app(log_dir)
    print(f"Dashboard: http://127.0.0.1:{port}")
    print(f"Reading alerts from {log_dir / 'alerts.jsonl'}")
    print("Press Ctrl+C to stop.")
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
