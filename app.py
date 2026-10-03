from flask import Flask, render_template, request
from datetime import datetime
from database import (
    create_database,
    record_simulation,
    save_awareness_score,
    create_incident_table,
    create_incident,
    update_incident_status,
    add_incident_timeline
)
app = Flask(__name__)
create_database()
create_incident_table()
import re
from urllib.parse import urlparse
SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".zip", ".work"]
SUSPICIOUS_DOMAIN_WORDS = [
    "login",
    "verify",
    "verification",
    "secure",
    "support",
    "account",
    "update",
    "confirm"
]
SUSPICIOUS_EMAIL_KEYWORDS = {
    "urgent": 5,
    "immediately": 5,
    "verify": 5,
    "verification": 5,
    "password": 5,
    "account suspended": 10,
    "account locked": 10,
    "click here": 5,
    "confirm": 5,
    "otp": 5,
    "payment": 5,
    "invoice": 5,
    "security alert": 5
}
def analyze_sender(sender):
    findings = []
    score = 0
    email_pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    if not re.match(email_pattern, sender):
        score += 30
        findings.append("Invalid or unusual email format")
    if "@" in sender:
        domain = sender.split("@")[-1].lower()
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score += 20
                findings.append(f"Suspicious domain extension: {tld}")
        for word in SUSPICIOUS_DOMAIN_WORDS:
            if word in domain:
                score += 10
                findings.append(f"Suspicious domain keyword: {word}")
        if domain.count("-") >= 2:
            score += 10
            findings.append("Domain contains multiple hyphens")
    score = min(score, 40)
    if score == 0:
        status = "Safe"
    elif score <= 20:
        status = "Suspicious"
    else:
        status = "High Risk"
    return {
        "score": score,
        "status": status,
        "findings": findings
    }
def analyze_url(url):

    findings = []
    score = 0

    if not url:
        return {
            "score": 0,
            "status": "Not Provided",
            "findings": []
        }

    url = url.strip().lower()

    # 1. Check HTTP
    if url.startswith("http://"):
        score += 15
        findings.append("URL does not use HTTPS")

    # 2. Parse URL
    try:
        parsed = urlparse(url)
        domain = parsed.netloc

        # 3. Check domain
        if not domain:
            score += 20
            findings.append("Invalid or unusual URL structure")

        # 4. Suspicious extension
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score += 20
                findings.append(
                    f"Suspicious URL domain extension: {tld}"
                )

        # 5. Suspicious keywords
        for word in SUSPICIOUS_DOMAIN_WORDS:
            if word in domain:
                score += 10
                findings.append(
                    f"Suspicious URL keyword: {word}"
                )

        # 6. Multiple hyphens
        if domain.count("-") >= 2:
            score += 10
            findings.append(
                "URL domain contains multiple hyphens"
            )

        # 7. IP address
        ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

        if re.match(ip_pattern, domain):
            score += 25
            findings.append(
                "URL uses an IP address instead of a domain name"
            )

    except Exception:
        score += 20
        findings.append("Unable to parse URL safely")

    # Maximum URL score = 40
    score = min(score, 40)

    # Classification
    if score == 0:
        status = "Safe"

    elif score <= 20:
        status = "Suspicious"

    else:
        status = "High Risk"

    # IMPORTANT: return the result
    return {
        "score": score,
        "status": status,
        "findings": findings
    }
def analyze_keywords(subject, content):
    findings = []
    score = 0
    text = f"{subject} {content}".lower()
    for keyword, points in SUSPICIOUS_EMAIL_KEYWORDS.items():
        if keyword in text:
            score += points
            findings.append(f"Suspicious keyword detected: {keyword}")
    score = min(score, 30)
    if score == 0:
        status = "Safe"
    elif score <= 15:
        status = "Suspicious"
    else:
        status = "High Risk"
    return {
        "score": score,
        "status": status,
        "findings": findings
    }
def calculate_risk_score(sender_result, url_result, keyword_result):

    sender_score = sender_result["score"]
    url_score = url_result["score"]
    keyword_score = keyword_result["score"]

    total_score = sender_score + url_score + keyword_score

    max_score = 40 + 40 + 30

    final_score = round((total_score / max_score) * 100)

    if final_score <= 30:
        classification = "SAFE"

    elif final_score <= 60:
        classification = "SUSPICIOUS"

    else:
        classification = "MALICIOUS"

    return {
        "score": final_score,
        "classification": classification
    }
@app.route("/", methods=["GET", "POST"])
def home():

    if request.method == "POST":

        sender = request.form.get("sender", "").strip()
        subject = request.form.get("subject", "").strip()
        content = request.form.get("content", "").strip()
        url = request.form.get("url", "").strip()

        # Input validation
        if not sender or not subject or not content:
            return "Please fill in Sender Email, Subject and Email Content."

        # Analyze email
        sender_result = analyze_sender(sender)
        url_result = analyze_url(url)
        keyword_result = analyze_keywords(subject, content)

        # Calculate final risk score
        risk_result = calculate_risk_score(
            sender_result,
            url_result,
            keyword_result
        )

        # Print results in terminal
        print("---- EMAIL RECEIVED ----")
        print("Sender:", sender)
        print("Subject:", subject)
        print("Content:", content)
        print("URL:", url)
        print("Sender Analysis:", sender_result)
        print("URL Analysis:", url_result)
        print("Keyword Analysis:", keyword_result)
        print("Risk Result:", risk_result)
        print("--------------------------")

        # Show result page
        return render_template(
            "result.html",
            sender=sender,
            subject=subject,
            content=content,
            url=url,
            sender_result=sender_result,
            url_result=url_result,
            keyword_result=keyword_result,
            risk_result=risk_result
        )

    return render_template("analyzer.html")
@app.route("/simulation")
def simulation():

    employee_name = "Demo Employee"

    return render_template(
        "simulation.html",
        employee_name=employee_name
    )


@app.route("/simulation-action", methods=["POST"])
def simulation_action():

    data = request.get_json()

    action = data.get("action")

    employee_name = "Demo Employee"

    email_subject = "Urgent: Verify Your Account"

    record_simulation(
        employee_name,
        email_subject,
        action
    )

    return {
        "message": f"Simulation action recorded: {action}"
    }
@app.route("/simulation-stats")
def simulation_stats():

    import sqlite3

    connection = sqlite3.connect("phishing_simulation.db")
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM simulations")
    total = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM simulations WHERE action = ?",
        ("Clicked",)
    )
    clicked = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM simulations WHERE action = ?",
        ("Reported",)
    )
    reported = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM simulations WHERE action = ?",
        ("Ignored",)
    )
    ignored = cursor.fetchone()[0]

    connection.close()

    if total > 0:
        reporting_rate = round((reported / total) * 100)
    else:
        reporting_rate = 0

    return render_template(
        "simulation_stats.html",
        total=total,
        clicked=clicked,
        reported=reported,
        ignored=ignored,
        reporting_rate=reporting_rate
    )
@app.route("/awareness")
def awareness():

    return render_template("awareness.html")


@app.route("/awareness-quiz", methods=["POST"])
def awareness_quiz():

    answers = {
        "q1": "a",
        "q2": "b",
        "q3": "b",
        "q4": "a",
        "q5": "a"
    }

    score = 0

    for question, correct_answer in answers.items():

        user_answer = request.form.get(question)

        if user_answer == correct_answer:
            score += 1

    percentage = round((score / 5) * 100)
    save_awareness_score(
    "Demo Employee",
    score,
    percentage
)
    return render_template(
        "awareness_result.html",
        score=score,
        percentage=percentage
    )
@app.route("/incident")
def incident():

    return render_template("incident.html")


@app.route("/create-incident", methods=["POST"])
def create_incident_route():

    reporter_name = request.form.get(
        "reporter_name",
        ""
    ).strip()

    email_subject = request.form.get(
        "email_subject",
        ""
    ).strip()

    description = request.form.get(
        "description",
        ""
    ).strip()

    severity = request.form.get(
        "severity",
        ""
    ).strip()

    if (
        not reporter_name
        or not email_subject
        or not description
        or not severity
    ):

        return "Please fill in all incident details."

    # Generate unique incident ID
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")

    incident_id = f"INC-{timestamp}"

    create_incident(
        incident_id,
        reporter_name,
        email_subject,
        description,
        severity
    )

    return render_template(
        "incident_success.html",
        incident_id=incident_id,
        reporter_name=reporter_name,
        email_subject=email_subject,
        severity=severity
    )
@app.route("/incident-status")
def incident_status():

    return render_template("incident_status.html")


@app.route("/update-status", methods=["POST"])
def update_status():

    incident_id = request.form.get(
        "incident_id",
        ""
    ).strip()

    new_status = request.form.get(
        "status",
        ""
    ).strip()

    if not incident_id or not new_status:
        return "Please provide Incident ID and Status."

    update_incident_status(
        incident_id,
        new_status
    )

    add_incident_timeline(
        incident_id,
        new_status
    )

    return f"""
        <h2>Incident status updated successfully.</h2>

        <p>Incident ID: {incident_id}</p>

        <p>New Status: {new_status}</p>

        <p>Timeline updated successfully.</p>

        <a href="/incident-status">
            Update Another Incident
        </a>
    """
@app.route("/incidents")
def incidents():

    import sqlite3

    connection = sqlite3.connect("phishing_simulation.db")

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM incidents
        ORDER BY id DESC
    """)

    incidents = cursor.fetchall()

    connection.close()

    return render_template(
        "incident_list.html",
        incidents=incidents
    )
@app.route("/dashboard")
def dashboard():

    import sqlite3

    connection = sqlite3.connect("phishing_simulation.db")
    cursor = connection.cursor()

    # Total simulations
    cursor.execute(
        "SELECT COUNT(*) FROM simulations"
    )
    total_simulations = cursor.fetchone()[0]

    # Clicked
    cursor.execute(
        "SELECT COUNT(*) FROM simulations WHERE action = ?",
        ("Clicked",)
    )
    clicked = cursor.fetchone()[0]

    # Reported
    cursor.execute(
        "SELECT COUNT(*) FROM simulations WHERE action = ?",
        ("Reported",)
    )
    reported = cursor.fetchone()[0]

    # Ignored
    cursor.execute(
        "SELECT COUNT(*) FROM simulations WHERE action = ?",
        ("Ignored",)
    )
    ignored = cursor.fetchone()[0]

    # Reporting rate
    if total_simulations > 0:
        reporting_rate = round(
            (reported / total_simulations) * 100
        )
    else:
        reporting_rate = 0

    # Total incidents
    cursor.execute(
        "SELECT COUNT(*) FROM incidents"
    )
    total_incidents = cursor.fetchone()[0]

    # Open incidents
    cursor.execute(
        "SELECT COUNT(*) FROM incidents WHERE status = ?",
        ("Open",)
    )
    open_incidents = cursor.fetchone()[0]

    # Investigating incidents
    cursor.execute(
        "SELECT COUNT(*) FROM incidents WHERE status = ?",
        ("Investigating",)
    )
    investigating_incidents = cursor.fetchone()[0]

    # Resolved incidents
    cursor.execute(
        "SELECT COUNT(*) FROM incidents WHERE status = ?",
        ("Resolved",)
    )
    resolved_incidents = cursor.fetchone()[0]

    # Awareness scores
    cursor.execute(
        "SELECT AVG(percentage) FROM awareness_scores"
    )
    average_awareness = cursor.fetchone()[0]

    if average_awareness is None:
        average_awareness = 0
    else:
        average_awareness = round(average_awareness)

    connection.close()

    return render_template(
        "dashboard.html",

        total_simulations=total_simulations,

        clicked=clicked,

        reported=reported,

        ignored=ignored,

        reporting_rate=reporting_rate,

        total_incidents=total_incidents,

        open_incidents=open_incidents,

        investigating_incidents=investigating_incidents,

        resolved_incidents=resolved_incidents,

        average_awareness=average_awareness
    )
if __name__ == "__main__":
    app.run(debug=True)