import os
import re
from datetime import datetime
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "phishshift-demo-key")

# Transparent, rule-based demo scanner. This can be replaced by a trained ML model
# when the model artifact and preprocessing pipeline are available.
URL_RE = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)
RISK_PATTERNS = [
    (r"\b(verify|verification|confirm|update)\s+(your\s+)?(account|password|identity|details|payment)\b", 22, "Account verification language"),
    (r"\b(urgent|immediately|action required|final warning|suspended|locked)\b", 18, "Urgency or threat language"),
    (r"\b(password|otp|one[- ]time passcode|pin|cvv|bank details|credit card)\b", 22, "Sensitive information requested"),
    (r"\b(prize|winner|won|claim your reward|free gift|lottery)\b", 14, "Unexpected prize or reward"),
    (r"\b(click here|open the link|tap here|login now)\b", 12, "Push to click or log in"),
    (r"\b(refund|delivery failed|package held|invoice attached)\b", 10, "Common lure wording"),
]
TRUSTED_HINTS = ["official website", "unsubscribe", "privacy policy"]

def scan_message(message):
    text = (message or "").strip()
    if not text:
        return {
            "label": "No message entered", "risk": 0, "level": "Unknown",
            "summary": "Paste a message to check its risk indicators.",
            "signals": [], "urls": [], "recommendations": ["Enter a message in the scanner."]
        }

    lower = text.lower()
    signals = []
    score = 0
    for pattern, weight, description in RISK_PATTERNS:
        if re.search(pattern, lower, re.IGNORECASE):
            score += weight
            signals.append({"title": description, "detail": "A potentially suspicious phrase was found.", "weight": weight})
    urls = URL_RE.findall(text)
    if urls:
        score += min(18, 6 * len(urls))
        signals.append({"title": "Link detected", "detail": f"{len(urls)} web link(s) found. Inspect the domain before opening.", "weight": min(18, 6 * len(urls))})
        suspicious_domains = [u for u in urls if re.search(r"(bit\.ly|tinyurl|t\.co|is\.gd|cutt\.ly|rb\.gy)", u, re.I)]
        if suspicious_domains:
            score += 12
            signals.append({"title": "Shortened URL", "detail": "A shortened link can hide the destination.", "weight": 12})
    if re.search(r"\b\d{4,8}\b", text) and re.search(r"\b(otp|code|passcode)\b", lower):
        score += 8
        signals.append({"title": "Possible one-time code context", "detail": "Never share a one-time code with someone who contacts you unexpectedly.", "weight": 8})
    if text.count("!") >= 3 or text.isupper() and len(text) > 15:
        score += 5
        signals.append({"title": "Unusual emphasis", "detail": "Excessive punctuation or all-caps wording can be a pressure tactic.", "weight": 5})

    score = min(100, score)
    if score >= 60:
        level, label = "High", "Likely suspicious"
        summary = "Several risk indicators were found. Do not click links or share information until you verify the sender independently."
    elif score >= 30:
        level, label = "Medium", "Use caution"
        summary = "Some risk indicators were found. Check the sender and destination carefully using a trusted channel."
    else:
        level, label = "Low", "Fewer risk indicators"
        summary = "This message has fewer indicators in this demo scan, but that does not guarantee it is safe."
    if not signals:
        signals.append({"title": "No common indicators detected", "detail": "Automated checks did not find the listed patterns.", "weight": 0})
    recommendations = [
        "Do not share passwords, PINs, CVVs, or one-time codes.",
        "Open the official app or type the known website address yourself instead of using a message link.",
        "Verify unexpected requests with the organization using contact details you already trust."
    ]
    return {
        "label": label, "risk": score, "level": level, "summary": summary,
        "signals": signals, "urls": urls, "recommendations": recommendations
    }

@app.route("/", methods=["GET", "POST"])
def index():
    message = ""
    result = None
    if request.method == "POST":
        message = request.form.get("message", "")
        result = scan_message(message)
    return render_template("index.html", message=message, result=result)

@app.route("/api/scan", methods=["POST"])
def api_scan():
    payload = request.get_json(silent=True) or {}
    message = payload.get("message", "")
    if not isinstance(message, str):
        return jsonify({"error": "message must be a string"}), 400
    return jsonify(scan_message(message))

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "PhishShift Message Risk Scanner"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
