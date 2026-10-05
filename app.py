"""
SOC Threat Intelligence & Alert Analysis Dashboard
==================================================
Main Flask application file. Contains all the routes the user interacts with.
Each route corresponds to a page or action in the web interface.
"""

# Flask is the main web framework — provides routing, sessions, and templating
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, make_response
from functools import wraps  # Used to build the login_required decorator

# Application configuration (API keys, secret keys, etc.)
from config import Config

# All database functions used by the routes
from database.db import (
    init_db, get_all_alerts, get_alert_by_id, get_alert_count,
    get_critical_high_alerts, update_alert_field,
    create_user, get_user_by_username, get_user_by_id, verify_password,
    save_result, get_user_stats, get_leaderboard, get_user_alert_history,
    set_user_alert_state, reset_user_alert_state, reset_all_user_states,
)

# Function that populates the database with the 15 pre-defined scenarios
from database.seed_data import seed_database as seed_alerts

# Threat intelligence service for IP and file hash lookups
from services.virustotal import lookup_ip, lookup_hash

# MITRE ATT&CK service for tactic and technique metadata
from services.mitre import get_tactic_info, get_technique_info

from collections import Counter  # Used to count tactic occurrences for the chart
import json
from datetime import datetime


# ============ APPLICATION SETUP ============
app = Flask(__name__)
app.config.from_object(Config)  # Load settings from config.py


# ============ SOC TEAM ============
# Team members displayed in the escalation dropdown
SOC_TEAM = {
    "l1": "You (L1 Analyst)",                       # The user themselves
    "l2_sarah": "Sarah Fleming (L2 Analyst)",       # Tier 2 analyst
    "l2_omar": "Omar Hassan (L2 Analyst)",          # Another Tier 2 analyst
    "manager": "David McCarthy (SOC Manager)",      # SOC Manager
}


# ============ DATABASE INITIALISATION ============
init_db()  # Creates the tables if they do not already exist
# On first run the database is empty — populate it with the 15 alert scenarios
if get_alert_count() == 0:
    seed_alerts()


# ============ AUTHENTICATION ============

def login_required(f):
    """
    Decorator that enforces authentication on protected routes.
    If the user is not logged in, redirects them to the login page.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def current_user():
    """Returns the currently logged-in user, or None if no one is logged in."""
    if "user_id" in session:
        return get_user_by_id(session["user_id"])
    return None


@app.context_processor
def inject_user():
    """
    Makes current_user available in every template automatically.
    Allows {{ current_user.display_name }} to be used in any template.
    """
    return dict(current_user=current_user())


# ============ LOGIN ROUTE ============
@app.route("/login", methods=["GET", "POST"])
def login():
    # If already logged in, skip the login page
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        # Look up the user in the database
        user = get_user_by_username(username)

        # verify_password compares the entered password against the stored salted hash
        if user and verify_password(user["password_hash"], password):
            # Credentials valid — start the session
            session["user_id"] = user["id"]
            session["display_name"] = user["display_name"]
            flash(f"Welcome back, {user['display_name']}!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "danger")

    return render_template("login.html")


# ============ REGISTRATION ROUTE ============
@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        display_name = request.form.get("display_name", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        # Input validation
        if len(username) < 3:
            flash("Username must be at least 3 characters.", "danger")
        elif len(password) < 4:
            flash("Password must be at least 4 characters.", "danger")
        elif password != confirm:
            flash("Passwords do not match.", "danger")
        else:
            # All checks passed — create the account (password is hashed by create_user)
            uid = create_user(username, password, display_name or username)
            if uid:
                # Automatic login after successful registration
                session["user_id"] = uid
                session["display_name"] = display_name or username
                flash(f"Account created! Welcome, {display_name or username}!", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Username already exists.", "danger")

    return render_template("register.html")


# ============ LOGOUT ROUTE ============
@app.route("/logout")
def logout():
    session.clear()  # Wipe the session
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ============ DASHBOARD ROUTE ============
@app.route("/")
@login_required
def dashboard():
    uid = session["user_id"]

    # Fetch all alerts with this user's individual state applied
    # (each user has their own status / verdict / assignee per alert)
    alerts = get_all_alerts(user_id=uid)

    # Aggregate statistics for the top of the dashboard
    stats = {
        "total": len(alerts),
        "awaiting": sum(1 for a in alerts if a.status == "Awaiting Action"),
        "in_progress": sum(1 for a in alerts if a.status == "In Progress"),
        "closed": sum(1 for a in alerts if a.status == "Closed"),
        "critical": sum(1 for a in alerts if a.severity == "Critical"),
        "high": sum(1 for a in alerts if a.severity == "High"),
        "medium": sum(1 for a in alerts if a.severity == "Medium"),
        "low": sum(1 for a in alerts if a.severity == "Low"),
    }

    # Build data for the MITRE ATT&CK bar chart (tactic name -> count)
    mitre_counter = Counter(a.mitre_tactic for a in alerts if a.mitre_tactic)
    mitre_labels = list(mitre_counter.keys())
    mitre_counts = list(mitre_counter.values())

    # The eight most-recent Critical/High alerts for the table at the bottom
    recent_alerts = get_critical_high_alerts(limit=8, user_id=uid)

    # Personal performance metrics (accuracy, average time, totals)
    user_stats = get_user_stats(uid)

    return render_template("dashboard.html", stats=stats, recent_alerts=recent_alerts,
                           mitre_labels=mitre_labels, mitre_counts=mitre_counts,
                           user_stats=user_stats)


# ============ ALERTS LIST ROUTE ============
@app.route("/alerts")
@login_required
def alerts_list():
    # Read filter values from URL query string
    severity = request.args.get("severity")
    status = request.args.get("status")
    difficulty = request.args.get("difficulty")

    # Fetch alerts with filters applied AND with this user's per-alert state
    alerts = get_all_alerts(severity=severity, status=status, difficulty=difficulty, user_id=session["user_id"])
    return render_template("alerts.html", alerts=alerts)


# ============ ALERT DETAIL ROUTE ============
@app.route("/alert/<int:alert_id>")
@login_required
def alert_detail(alert_id):
    # Fetch the alert with this user's specific state
    alert = get_alert_by_id(alert_id, user_id=session["user_id"])
    if not alert:
        return "Alert not found", 404

    # Decode the JSON evidence field into a Python dict for the template
    details = {}
    if alert.details:
        try:
            details = json.loads(alert.details)
        except (json.JSONDecodeError, TypeError):
            details = {}

    # Threat intelligence lookup — only for non-internal IPs and file hashes
    vt_data = None
    if alert.source_ip and not alert.source_ip.startswith("10."):
        vt_data = lookup_ip(alert.source_ip)
    elif alert.file_hash:
        vt_data = lookup_hash(alert.file_hash)

    # MITRE ATT&CK enrichment — descriptions and mitigations
    mitre_tactic = get_tactic_info(alert.mitre_tactic) if alert.mitre_tactic else None
    mitre_technique = get_technique_info(alert.mitre_technique_id) if alert.mitre_technique_id else None

    # Quiz questions (stored as JSON in the database)
    questions = []
    if alert.questions:
        try:
            questions = json.loads(alert.questions)
        except (json.JSONDecodeError, TypeError):
            questions = []

    return render_template("alert_detail.html", alert=alert, details=details,
                           vt_data=vt_data, mitre_tactic=mitre_tactic,
                           mitre_technique=mitre_technique, questions=questions,
                           soc_team=SOC_TEAM)


# ============ ALERT UPDATE ROUTE (assign / submit / reopen) ============
@app.route("/alert/<int:alert_id>/update", methods=["POST"])
@login_required
def update_alert(alert_id):
    uid = session["user_id"]
    alert = get_alert_by_id(alert_id, user_id=uid)
    if not alert:
        return "Alert not found", 404

    action = request.form.get("action")

    # ----- Action: Assign alert to current user -----
    if action == "assign":
        # Per-user state — does NOT affect what other users see
        set_user_alert_state(uid, alert_id, assignee="You (L1 Analyst)", status="In Progress")
        flash("Alert assigned to you. Begin your analysis.", "warning")

    # ----- Action: Submit final triage decision -----
    elif action == "submit_decision":
        verdict = request.form.get("verdict", "None")           # True Positive / False Positive
        escalate_to = request.form.get("escalate_to", "close")  # close / escalate_l2 / escalate_manager
        comment = request.form.get("comment", "").strip()
        time_spent = int(request.form.get("time_spent", 0))     # From the JS stopwatch
        quiz_score = int(request.form.get("quiz_score", 0))
        quiz_total = int(request.form.get("quiz_total", 0))

        # Compare the analyst's choice against the stored correct answer
        is_verdict_correct = (verdict == alert.correct_verdict)
        is_action_correct = (escalate_to == alert.correct_action)
        both_correct = is_verdict_correct and is_action_correct

        # Map escalation choice to the assignee that will appear next to the alert
        assignee_map = {
            "close": "You (L1 Analyst)",
            "escalate_l2": SOC_TEAM["l2_sarah"],
            "escalate_manager": SOC_TEAM["manager"],
        }
        new_assignee = assignee_map.get(escalate_to, alert.assignee)
        new_status = "Closed" if escalate_to == "close" else "In Progress"

        # Save the new per-user state for this alert
        set_user_alert_state(uid, alert_id, status=new_status, verdict=verdict,
                             analyst_comment=comment, assignee=new_assignee)

        # Record the attempt in the results table — drives the leaderboard
        save_result(
            user_id=uid, alert_id=alert_id,
            verdict_given=verdict, action_given=escalate_to,
            is_verdict_correct=is_verdict_correct, is_action_correct=is_action_correct,
            time_spent=time_spent, quiz_score=quiz_score, quiz_total=quiz_total,
        )

        # Show the evaluation feedback message
        if both_correct:
            flash(f"CORRECT! {alert.correct_explanation}", "success")
        else:
            parts = []
            if not is_verdict_correct:
                parts.append(f"Verdict should be: {alert.correct_verdict}")
            if not is_action_correct:
                action_names = {"close": "Close", "escalate_l2": "Escalate to L2", "escalate_manager": "Escalate to Manager"}
                parts.append(f"Action should be: {action_names.get(alert.correct_action, alert.correct_action)}")
            flash(f"INCORRECT. {' | '.join(parts)}. {alert.correct_explanation}", "danger")

    # ----- Action: Reopen the alert (try again from scratch) -----
    elif action == "reopen":
        reset_user_alert_state(uid, alert_id)
        flash("Alert reopened.", "warning")

    return redirect(url_for("alert_detail", alert_id=alert_id))


# ============ RESET ALL ALERTS (current user only) ============
@app.route("/reset-all", methods=["POST"])
@login_required
def reset_all():
    # Only resets THIS user's state — does not affect other users
    reset_all_user_states(session["user_id"])
    flash("All your alerts have been reset.", "warning")
    return redirect(url_for("alerts_list"))


# ============ SCOREBOARD ROUTE ============
@app.route("/scoreboard")
@login_required
def scoreboard():
    user_stats = get_user_stats(session["user_id"])
    history = get_user_alert_history(session["user_id"])
    leaderboard = get_leaderboard()
    return render_template("scoreboard.html", user_stats=user_stats,
                           history=history, leaderboard=leaderboard)


# ============ PDF REPORT ROUTE ============
@app.route("/report/pdf")
@login_required
def generate_pdf():
    user = current_user()
    stats = get_user_stats(session["user_id"])
    history = get_user_alert_history(session["user_id"])

    # Render a print-styled HTML page; the user saves it as PDF via the browser
    html = render_template("report_pdf.html", user=user, stats=stats, history=history,
                           generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))

    response = make_response(html)
    response.headers["Content-Type"] = "text/html"
    return response


# ============ THREAT INTELLIGENCE LOOKUP ROUTE ============
@app.route("/threat-intel", methods=["GET", "POST"])
@login_required
def threat_intel():
    result = None
    indicator = None
    lookup_type = "ip"

    if request.method == "POST":
        lookup_type = request.form.get("lookup_type", "ip")
        indicator = request.form.get("indicator", "").strip()

        if indicator:
            # Live VirusTotal lookup (uses real API for indicators not in the mock DB)
            result = lookup_ip(indicator) if lookup_type == "ip" else lookup_hash(indicator)

    return render_template("threat_intel.html", result=result, indicator=indicator, lookup_type=lookup_type)


# ============ APPLICATION ENTRY POINT ============
if __name__ == "__main__":
    # debug=True shows errors in the browser and reloads on file changes
    # host=0.0.0.0 makes the server accessible from the local network
    app.run(debug=True, host="0.0.0.0", port=5000)
