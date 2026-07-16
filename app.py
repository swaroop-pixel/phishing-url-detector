"""Flask routes for rendering and managing detector scans."""
import csv
import io
import json
import time

from flask import Flask, Response, jsonify, render_template, request

from database import clear_history, delete_scan, get_recent_scans, init_db, save_scan
from detector import check_url

app = Flask(__name__)
init_db()


def _run_scan(url):
    started = time.perf_counter()
    result = check_url(url)
    result["duration_ms"] = round((time.perf_counter() - started) * 1000)
    result["scan_status"] = "Completed"
    result["meter_percent"] = max(0, min(int(result["score"]), 100))
    domain_info = result.pop("domain_info", {})
    result.update(domain_info)
    result["created"] = result.get("created_date", "Unavailable")
    result["expiry"] = result.get("expiry_date", "Unavailable")
    result["ip"] = result.get("ip_address", "Unavailable")
    result["hosting"] = result.get("hosting_provider", "Unavailable")
    result["ssl"] = result.get("ssl_status", "Unavailable")
    save_scan(result)
    return result


@app.route("/", methods=["GET", "POST"])
def home():
    result = _run_scan(request.form["url"].strip()) if request.method == "POST" and request.form.get("url", "").strip() else None
    return render_template("index.html", result=result, history=get_recent_scans())


@app.post("/history/<int:scan_id>")
def remove_history_row(scan_id):
    if not delete_scan(scan_id):
        return jsonify({"ok": False, "message": "Scan was not found."}), 404
    return jsonify({"ok": True, "message": "Scan deleted."})


@app.post("/clear-history")
def remove_all_history():
    clear_history()
    return jsonify({"ok": True, "message": "Scan history cleared."})


@app.get("/history/export.csv")
def export_history():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Date", "Time", "URL", "Risk", "Score", "Confidence", "Flags", "Duration (ms)"])
    for scan in get_recent_scans(limit=10000):
        flags = "; ".join(json.loads(scan["flags"] or "[]"))
        date, _, scan_time = scan["checked_at"].partition(" ")
        writer.writerow([date, scan_time, scan["url"], scan["risk"], scan["score"], scan["confidence"], flags, scan["duration_ms"]])
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=phishing-scan-history.csv"})


if __name__ == "__main__":
    app.run(debug=True)
