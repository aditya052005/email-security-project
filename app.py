from flask import Flask, render_template, request
import re
from urllib.parse import urlparse
from model import predict_email

app = Flask(__name__)

history = []


def analyze_urls(email):
    """
    Analyze URLs found inside an email.
    Returns risk score, reasons and analysis categories.
    """

    url_score = 0
    url_reasons = []
    urls = re.findall(r'https?://[^\s]+', email)

    for url in urls:

        clean_url = url.rstrip(".,!?;:)")

        parsed = urlparse(clean_url)
        domain = parsed.netloc.lower()

        # HTTP instead of HTTPS
        if parsed.scheme == "http":
            url_score += 8
            url_reasons.append(
                "Insecure HTTP connection detected in URL."
            )

        # Login-related words
        if any(word in clean_url.lower()
               for word in ["login", "signin", "verify", "account"]):

            url_score += 8
            url_reasons.append(
                "URL contains login or verification-related terms."
            )

        # Suspicious domain keywords
        if any(word in domain
               for word in ["secure", "update", "verify", "support"]):

            url_score += 7
            url_reasons.append(
                "Domain contains suspicious security-related keywords."
            )

        # IP address instead of normal domain
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):

            url_score += 15
            url_reasons.append(
                "URL uses an IP address instead of a normal domain name."
            )

        # Very long URL
        if len(clean_url) > 100:

            url_score += 5
            url_reasons.append(
                "Unusually long URL detected."
            )

        # Multiple subdomains
        if domain.count(".") >= 3:

            url_score += 5
            url_reasons.append(
                "URL contains multiple subdomains."
            )

    return min(url_score, 40), url_reasons, urls


@app.route("/")
def home():

    return render_template(
        "index.html",
        history=history,
        total=len(history),
        high=sum(
            1 for item in history
            if item["risk"] == "HIGH RISK"
        ),
        safe=sum(
            1 for item in history
            if item["risk"] == "LOW RISK"
        ),
        ml_result=None,
        ml_confidence=None,
        detected_urls=[]
    )


@app.route("/analyze", methods=["POST"])
def analyze():

    email_original = request.form.get("email", "")
    email = email_original.lower()

    score = 0
    reasons = []
    categories = []

    # --------------------------------
    # Language Analysis
    # --------------------------------

    if "urgent" in email or "immediately" in email:

        score += 15

        reasons.append(
            "Urgent or pressure-based language detected."
        )

        categories.append("Language Analysis")

    # --------------------------------
    # Content Analysis
    # --------------------------------

    if "verify" in email or "confirm" in email:

        score += 12

        reasons.append(
            "Account verification request detected."
        )

        categories.append("Content Analysis")

    # --------------------------------
    # Threat Analysis
    # --------------------------------

    if "suspended" in email or "blocked" in email:

        score += 12

        reasons.append(
            "Account suspension or blocking warning detected."
        )

        categories.append("Threat Analysis")

    # --------------------------------
    # Credential Analysis
    # --------------------------------

    if "password" in email or "otp" in email:

        score += 20

        reasons.append(
            "Request for sensitive information detected."
        )

        categories.append("Credential Analysis")

    # --------------------------------
    # Advanced URL Analysis
    # --------------------------------

    url_score, url_reasons, detected_urls = analyze_urls(email)

    if detected_urls:

        score += url_score

        reasons.extend(url_reasons)

        categories.append("URL Analysis")

        categories.append("URL Reputation")

    # --------------------------------
    # Machine Learning Analysis
    # --------------------------------

    ml_result, ml_probability = predict_email(email)

    if ml_result == "PHISHING":

        ml_confidence = round(
            ml_probability * 100,
            2
        )

        if ml_probability >= 0.60:

            score += 15

        reasons.append(
            f"ML model classified the email as phishing "
            f"({ml_confidence}% confidence)."
        )

        categories.append("ML Classification")

    else:

        ml_confidence = round(
            (1 - ml_probability) * 100,
            2
        )

        reasons.append(
            f"ML model classified the email as legitimate "
            f"({ml_confidence}% confidence)."
        )

        categories.append("ML Classification")

    # --------------------------------
    # Final Score
    # --------------------------------

    score = min(score, 100)

    if score >= 50:

        risk_level = "HIGH RISK"
        risk_class = "high"

    elif score >= 30:

        risk_level = "MEDIUM RISK"
        risk_class = "medium"

    else:

        risk_level = "LOW RISK"
        risk_class = "low"

    categories = list(dict.fromkeys(categories))

    # --------------------------------
    # History
    # --------------------------------

    history.insert(
        0,
        {
            "risk": risk_level,
            "score": score
        }
    )

    if len(history) > 5:

        history.pop()

    total = len(history)

    high = sum(
        1 for item in history
        if item["risk"] == "HIGH RISK"
    )

    safe = sum(
        1 for item in history
        if item["risk"] == "LOW RISK"
    )

    # --------------------------------
    # Dashboard
    # --------------------------------

    return render_template(
        "index.html",

        result=risk_level,

        score=score,

        risk_class=risk_class,

        reasons=reasons,

        categories=categories,

        history=history,

        total=total,

        high=high,

        safe=safe,

        ml_result=ml_result,

        ml_confidence=ml_confidence,

        detected_urls=detected_urls
    )


if __name__ == "__main__":
    app.run(debug=True)