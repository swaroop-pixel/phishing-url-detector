"""Flask routes for rendering and managing detector scans."""
import csv
import io
import json
import logging
import time

from flask import Flask, Response, jsonify, render_template, request

from database import clear_history, delete_scan, get_recent_scans, init_db, save_scan
from detector import check_url

LOGGER = logging.getLogger(__name__)

app = Flask(__name__)
init_db()

_SAFE_INT_DEFAULT = 0


def _safe_int(value, default=_SAFE_INT_DEFAULT, lo=0, hi=100):
    """Coerces value to an int clamped to [lo, hi]. detector.py already
    guarantees 'score'/'confidence' are always ints in range, but this is
    defense in depth at the app layer - a None/garbage value here should
    degrade to a safe default rather than raising (that's exactly the
    int(None) crash this replaces).
    """
    try:
        return max(lo, min(int(round(float(value))), hi))
    except (TypeError, ValueError):
        LOGGER.warning("Expected a number but got %r - defaulting to %s", value, default)
        return default


def _run_scan(url):
    """Runs a scan and returns a fully-populated result dict. Never raises:
    detector.py's check_url() already guarantees this, but the try/except
    here is a second, independent line of defense - a scan failing must
    never turn into a 500 error page for the user.
    """
    started = time.perf_counter()
    try:
        result = check_url(url)
        if not isinstance(result, dict):
            raise TypeError(f"check_url() returned {type(result)}, expected dict")
    except Exception as error:
        LOGGER.exception("check_url() failed for url=%r: %s", url, error)
        result = {
            "url": url, "score": 0, "risk": "Medium", "confidence": 0,
            "recommendation": "Proceed with Caution", "flags": [f"Scan could not complete: {error}"],
            "rules": [], "whois": {"available": False, "created_date": "Unavailable", "age_days": "Unavailable"},
            "domain_info": {}, "metadata": {},
        }

    result["duration_ms"] = round((time.perf_counter() - started) * 1000)
    result["scan_status"] = "Completed"
    result["score"] = _safe_int(result.get("score"), default=0)
    result["confidence"] = _safe_int(result.get("confidence"), default=0)
    result["risk"] = result.get("risk") if isinstance(result.get("risk"), str) else "Medium"
    result["flags"] = result.get("flags") if isinstance(result.get("flags"), list) else []
    result["recommendation"] = result.get("recommendation") if isinstance(result.get("recommendation"), str) else "Unavailable"
    result["meter_percent"] = result["score"]

    domain_info = result.pop("domain_info", {})
    if not isinstance(domain_info, dict):
        LOGGER.warning("domain_info was %r (expected dict) - substituting empty dict", type(domain_info))
        domain_info = {}
    result.update(domain_info)
    result["created"] = result.get("created_date") or "Unavailable"
    result["expiry"] = result.get("expiry_date") or "Unavailable"
    result["ip"] = result.get("ip_address") or "Unavailable"
    result["hosting"] = result.get("hosting_provider") or "Unavailable"
    result["ssl"] = result.get("ssl_status") or "Unavailable"

    try:
        save_scan(result)
    except Exception as error:
        # A history-write failure should never hide the scan result the
        # user is waiting on - log it and keep going.
        LOGGER.exception("save_scan() failed for url=%r: %s", url, error)

    return result


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    if request.method == "POST" and request.form.get("url", "").strip():
        result = _run_scan(request.form["url"].strip())
    try:
        history = get_recent_scans()
    except Exception as error:
        LOGGER.exception("get_recent_scans() failed: %s", error)
        history = []
    return render_template("index.html", result=result, history=history)


@app.post("/history/<int:scan_id>")
def remove_history_row(scan_id):
    try:
        if not delete_scan(scan_id):
            return jsonify({"ok": False, "message": "Scan was not found."}), 404
    except Exception as error:
        LOGGER.exception("delete_scan(%s) failed: %s", scan_id, error)
        return jsonify({"ok": False, "message": "Could not delete scan."}), 500
    return jsonify({"ok": True, "message": "Scan deleted."})


@app.post("/clear-history")
def remove_all_history():
    try:
        clear_history()
    except Exception as error:
        LOGGER.exception("clear_history() failed: %s", error)
        return jsonify({"ok": False, "message": "Could not clear history."}), 500
    return jsonify({"ok": True, "message": "Scan history cleared."})


@app.get("/history/export.csv")
def export_history():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Date", "Time", "URL", "Risk", "Score", "Confidence", "Flags", "Duration (ms)"])
    try:
        scans = get_recent_scans(limit=10000)
    except Exception as error:
        LOGGER.exception("get_recent_scans() failed during export: %s", error)
        scans = []
    for scan in scans:
        try:
            flags = "; ".join(json.loads(scan["flags"] or "[]"))
        except (TypeError, ValueError, json.JSONDecodeError):
            flags = ""
        date, _, scan_time = (scan["checked_at"] or "").partition(" ")
        writer.writerow([date, scan_time, scan["url"], scan["risk"], scan["score"], scan["confidence"], flags, scan["duration_ms"]])
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=phishing-scan-history.csv"})


if __name__ == "__main__":
    app.run(debug=True)