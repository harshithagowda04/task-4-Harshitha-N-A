import io
import logging
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlsplit

from flask import Flask, abort, g, jsonify, redirect, render_template, request, send_file, session, url_for
from markupsafe import escape

from detection.email_analyzer import analyze_email
from detection.url_analyzer import analyze_url, extract_urls
from database.db import get_db, init_db, close_db

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get("PHISHGUARD_SECRET", "local-educational-app"),
                  DATABASE=os.environ.get("PHISHGUARD_DB", os.path.join(BASE_DIR, "phishguard.sqlite3")),
                  MAX_CONTENT_LENGTH=200_000)
app.teardown_appcontext(close_db)
logging.basicConfig(level=logging.INFO)

@app.before_request
def csrf_check():
    if request.method == "POST" and request.values.get("csrf_token", (request.get_json(silent=True) or {}).get("csrf_token")) != session.get("csrf_token"):
        if request.is_json:
            return jsonify(error="Invalid form token. Refresh and try again."), 400
        abort(400)

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:"
    return response

@app.context_processor
def common_context():
    token=session.get("csrf_token")
    if token is None:
        token=secrets.token_urlsafe(32)
        session["csrf_token"]=token
    return {"csrf_token": token}

@app.route("/")
def index():
    row = get_db().execute("SELECT COUNT(*) total, SUM(verdict='PHISHING') phish, SUM(verdict='SUSPICIOUS') suspicious, SUM(verdict='SAFE') safe FROM analyses").fetchone()
    return render_template("index.html", stats=dict(row))

@app.route("/dashboard")
def dashboard():
    db = get_db()
    stats = db.execute("SELECT COUNT(*) total, COALESCE(SUM(verdict='PHISHING'),0) phishing, COALESCE(SUM(verdict='SUSPICIOUS'),0) suspicious, COALESCE(SUM(verdict='SAFE'),0) safe FROM analyses").fetchone()
    recent = db.execute("SELECT id,subject,sender,verdict,score,created_at FROM analyses ORDER BY id DESC LIMIT 6").fetchall()
    return render_template("dashboard.html", stats=stats, recent=recent)

@app.route("/analyzer", methods=["GET","POST"])
def analyzer():
    if request.method == "POST":
        data = request.form
        return _save_email(data)
    return render_template("analyzer.html")

@app.post("/api/analyze")
def api_analyze():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict): return jsonify(error="Expected a JSON object."), 400
    return _save_email(data, json_response=True)

def _save_email(data, json_response=False):
    sender = str(data.get("sender", "")).strip()[:254]
    recipient = str(data.get("recipient", "")).strip()[:254]
    subject = str(data.get("subject", "")).strip()[:300]
    body = str(data.get("body", "")).strip()[:50000]
    if not sender or not subject or not body:
        msg = "Sender, subject, and message body are required."
        return (jsonify(error=msg), 400) if json_response else (render_template("analyzer.html", error=msg, form=data), 400)
    if len(body) < 2:
        return (jsonify(error="Message body is too short."), 400) if json_response else (render_template("analyzer.html", error="Message body is too short.", form=data), 400)
    address_re=r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+"
    if not re.fullmatch(address_re, sender) or (recipient and not re.fullmatch(address_re, recipient)):
        msg="Enter a valid sender address and, if supplied, a valid recipient address."
        return (jsonify(error=msg), 400) if json_response else (render_template("analyzer.html", error=msg, form=data), 400)
    result = analyze_email(sender, subject, body)
    db = get_db()
    cur = db.execute("INSERT INTO analyses(sender,recipient,subject,body,verdict,score,risk,keywords,urls,flags,explanation,recommendations,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (sender,recipient,subject,body,result["verdict"],result["score"],result["risk"],"|".join(result["keywords"]),"|".join(result["urls"]),"|".join(f["title"] for f in result["flags"]),"\n".join(result["explanations"]),"\n".join(result["recommendations"]),datetime.now(timezone.utc).isoformat(timespec="seconds")))
    aid = cur.lastrowid
    for url in result["urls"]:
        ur = analyze_url(url)
        db.execute("INSERT INTO extracted_urls(analysis_id,url,score,indicators) VALUES(?,?,?,?)", (aid,url,ur["score"],"|".join(ur["indicators"])))
    for flag in result["flags"]:
        db.execute("INSERT INTO detected_indicators(analysis_id,title,detail,weight) VALUES(?,?,?,?)", (aid,flag["title"],flag["detail"],flag["weight"]))
    db.commit()
    if json_response: return jsonify(id=aid, **result)
    return redirect(url_for("report", analysis_id=aid))

@app.route("/results/<int:analysis_id>")
def report(analysis_id):
    row = get_db().execute("SELECT * FROM analyses WHERE id=?",(analysis_id,)).fetchone()
    if not row: abort(404)
    return render_template("report.html", record=row, flags=get_db().execute("SELECT * FROM detected_indicators WHERE analysis_id=?",(analysis_id,)).fetchall(), urls=get_db().execute("SELECT * FROM extracted_urls WHERE analysis_id=?",(analysis_id,)).fetchall())

@app.get("/report/<int:analysis_id>.txt")
def download_report(analysis_id):
    row = get_db().execute("SELECT * FROM analyses WHERE id=?",(analysis_id,)).fetchone()
    if not row: abort(404)
    text = f"PHISHGUARD — PHISHING AWARENESS & EMAIL THREAT ANALYSIS\nAnalysis ID: {row['id']}\nDate: {row['created_at']}\nSender: {row['sender']}\nRecipient: {row['recipient']}\nSubject: {row['subject']}\nVerdict: {row['verdict']}\nRisk: {row['score']}/100 ({row['risk']})\n\nKeywords: {row['keywords']}\nURLs: {row['urls']}\nRed flags: {row['flags']}\n\nExplanation:\n{row['explanation']}\n\nRecommendations:\n{row['recommendations']}\n\nHeuristic educational assessment; not a guaranteed security verdict.\n"
    return send_file(io.BytesIO(text.encode("utf-8")), as_attachment=True, download_name=f"phishguard-report-{analysis_id}.txt", mimetype="text/plain; charset=utf-8")

@app.route("/url-scanner", methods=["GET","POST"])
def url_scanner():
    result = None
    if request.method == "POST":
        raw = request.form.get("url", "").strip()[:2048]
        result = analyze_url(raw)
    return render_template("url_scanner.html", result=result)

@app.post("/api/scan-url")
def api_scan_url():
    data = request.get_json(silent=True) or {}
    return jsonify(analyze_url(str(data.get("url", ""))[:2048]))

@app.route("/history")
def history():
    q = request.args.get("q","").strip()[:100]
    verdict = request.args.get("verdict","").upper()
    order = "ASC" if request.args.get("sort")=="oldest" else "DESC"
    sql = "SELECT id,subject,sender,verdict,score,risk,created_at FROM analyses WHERE (subject LIKE ? OR sender LIKE ?)"
    params = [f"%{q}%",f"%{q}%"]
    if verdict in ("SAFE","SUSPICIOUS","PHISHING"):
        sql += " AND verdict=?"; params.append(verdict)
    rows = get_db().execute(sql+f" ORDER BY id {order}",params).fetchall()
    return render_template("history.html", records=rows, q=q, verdict=verdict)

@app.post("/history/<int:analysis_id>/delete")
def delete_analysis(analysis_id):
    db=get_db(); db.execute("DELETE FROM analyses WHERE id=?",(analysis_id,)); db.commit()
    return redirect(url_for("history"))

@app.post("/history/clear")
def clear_history():
    db=get_db(); db.execute("DELETE FROM analyses"); db.execute("DELETE FROM sqlite_sequence WHERE name IN ('analyses','extracted_urls','detected_indicators')"); db.commit()
    return redirect(url_for("history"))

@app.route("/awareness")
def awareness(): return render_template("awareness.html")
SAMPLES = [
 {"name":"Bank account suspension","sender":"security@mybank-alert.example","subject":"Your account is suspended","body":"Dear customer, urgent action required. Verify your account immediately to restore access: http://mybank.example.verify-login.co/account. Reply with your password if the link fails."},
 {"name":"Package delivery fee","sender":"delivery@parcel-notice.example","subject":"Delivery attempt failed","body":"Hello customer, your package is waiting. Pay a small redelivery fee today: http://bit.ly/3parcel. Your parcel will be returned unless you act now."},
 {"name":"Password reset scam","sender":"helpdesk@company-passwords.example","subject":"Password expired — confirm now","body":"Your password expired. Click immediately and confirm your identity at http://192.0.2.45/login to avoid losing access."},
 {"name":"Lottery prize","sender":"winner@global-rewards.example","subject":"Congratulations, you won!","body":"Congratulations, you won a free gift! Claim your reward within one hour. Send your bank account details to arrange payment."},
 {"name":"Fake job offer","sender":"careers@hiring-team.example","subject":"Remote role — offer attached","body":"Dear applicant, you have been selected for a high paying remote role. Pay a refundable onboarding fee and send your identity documents today. Open the attached file to begin."},
 {"name":"Corporate invoice","sender":"billing@vendor-payments.example","subject":"Overdue invoice — immediate payment","body":"Hello accounts payable, update payment details immediately to avoid legal action. Review invoice: http://vendor-payments.example.invoice-review.net/pay"},
 {"name":"Social verification","sender":"verify@social-support.example","subject":"Unusual login attempt","body":"We detected an unusual login attempt. Confirm your identity and password now: http://social.example.security-check.co/verify"},
 {"name":"Routine notification (legitimate style)","sender":"updates@library.example","subject":"Your monthly reading summary","body":"Hello Alex, your monthly reading summary is ready in your library account. You can open the app directly whenever convenient. No action is required."},
]
@app.route("/samples")
def samples(): return render_template("sample_lab.html", samples=SAMPLES)
@app.get("/samples/<int:index>")
def sample(index):
    if index<0 or index>=len(SAMPLES): abort(404)
    return jsonify(SAMPLES[index])
@app.route("/settings")
def settings(): return render_template("settings.html")
@app.route("/about")
def about(): return render_template("about.html")
@app.errorhandler(404)
def not_found(e): return render_template("404.html"),404
@app.errorhandler(500)
def server_error(e): app.logger.exception("Request failed"); return render_template("500.html"),500

with app.app_context(): init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT",5000)), debug=False)
