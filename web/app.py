import os
import sys
import json
from pathlib import Path
from flask import Flask, render_template, jsonify, send_file, abort

app = Flask(__name__)

BBRECON_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(BBRECON_DIR, "results")

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/api/scans")
def list_scans():
    scans = []
    results_path = Path(RESULTS_DIR)
    if not results_path.exists():
        return jsonify([])
    
    # Only look at subdirectories (each target is a subfolder)
    for item in sorted(results_path.iterdir(), reverse=True):
        if not item.is_dir():
            continue  # Skip files directly in results/
        report_file = item / "report.json"
        if report_file.exists():
            try:
                with open(report_file) as f:
                    data = json.load(f)
                scans.append({
                    "target": data.get("target", item.name),
                    "date": data.get("start_time", ""),
                    "subdomains": len(data.get("subdomains", [])),
                    "alive": len(data.get("alive_hosts", {})),
                    "takeovers": len(data.get("takeovers", [])),
                    "vulns": len(data.get("nuclei_vulns", [])),
                    "secrets": sum(len(s.get("secrets", [])) for s in data.get("js_analysis", [])),
                    "path": item.name
                })
            except:
                pass
    
    return jsonify(scans[:100])

@app.route("/report/<target_name>")
def view_report(target_name):
    """Serve HTML report for a target"""
    # Security: prevent path traversal
    target_name = target_name.replace("/", "").replace("..", "").replace("\\", "")
    
    report_file = os.path.join(RESULTS_DIR, target_name, "report.html")
    report_file = os.path.abspath(report_file)
    
    if os.path.exists(report_file):
        return send_file(report_file)
    
    # Fallback: find any report.html
    for d in Path(RESULTS_DIR).iterdir():
        if d.is_dir():
            rf = d / "report.html"
            if rf.exists():
                return send_file(str(rf))
    
    abort(404)

@app.route("/debug")
def debug_view():
    lines = [f"<h2>Results Directory: {RESULTS_DIR}</h2>"]
    lines.append(f"<p>Exists: {os.path.exists(RESULTS_DIR)}</p>")
    
    results_path = Path(RESULTS_DIR)
    if results_path.exists():
        lines.append("<h3>Contents:</h3><ul>")
        for f in sorted(results_path.rglob("*")):
            try:
                rel = f.relative_to(RESULTS_DIR)
                icon = "📄" if f.is_file() else "📁"
                lines.append(f"<li>{icon} {rel}</li>")
            except:
                pass
        lines.append("</ul>")
    
    return "".join(lines)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
