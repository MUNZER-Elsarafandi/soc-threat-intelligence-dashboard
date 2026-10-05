"""
Database module
=================
Handles all database operations:
- Schema creation
- User management (registration, password hashing)
- Alert state tracking
- Scoring and leaderboard
- Per-user alert state isolation
"""

import sqlite3
import os
import hashlib  # For password hashing (SHA-256)
import secrets  # For generating cryptographically secure random salts
from datetime import datetime

# Path to the SQLite database file (project root)
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "soc_dashboard.db")


def get_db():
    """Open a new database connection that returns rows as dicts."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Return rows as dict-like objects, not tuples
    return conn


def init_db():
    """Create all database tables if they do not already exist."""
    conn = get_db()

    # ----- Alerts table -----
    # Stores the 15 scenarios with their evidence and correct answers
    conn.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            difficulty TEXT DEFAULT 'Medium',
            source_ip TEXT,
            destination_ip TEXT,
            file_hash TEXT,
            cve_id TEXT,
            mitre_tactic TEXT,
            mitre_technique_id TEXT,
            mitre_technique_name TEXT,
            status TEXT DEFAULT 'Awaiting Action',
            assignee TEXT DEFAULT 'None',
            verdict TEXT DEFAULT 'None',
            analyst_comment TEXT,
            details TEXT,
            correct_verdict TEXT,
            correct_action TEXT,
            correct_explanation TEXT,
            questions TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # ----- Users table -----
    # Analyst accounts with salted SHA-256 password hashes
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL,
            role TEXT DEFAULT 'analyst',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # ----- Results table -----
    # Records every triage attempt; drives accuracy stats and leaderboard
    conn.execute('''
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            alert_id INTEGER NOT NULL,
            verdict_given TEXT,
            action_given TEXT,
            is_verdict_correct INTEGER DEFAULT 0,
            is_action_correct INTEGER DEFAULT 0,
            is_both_correct INTEGER DEFAULT 0,
            time_spent_seconds INTEGER DEFAULT 0,
            quiz_score INTEGER DEFAULT 0,
            quiz_total INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
        )
    ''')
    # ----- User alert state table -----
    # CRITICAL: per-user state for each alert.
    # When Munzer closes an alert, Sarah still sees it as Awaiting Action.
    # Each row links a user_id + alert_id with that user's individual state.
    conn.execute('''
        CREATE TABLE IF NOT EXISTS user_alert_state (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            alert_id INTEGER NOT NULL,
            status TEXT DEFAULT 'Awaiting Action',
            assignee TEXT DEFAULT 'None',
            verdict TEXT DEFAULT 'None',
            analyst_comment TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, alert_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
        )
    ''')
    conn.commit()
    conn.close()


def hash_password(password):
    """
    Hash a password using SHA-256 with a unique random salt.
    The salt prevents rainbow-table attacks.
    Returned format: "salt:hash".
    """
    salt = secrets.token_hex(16)  # Generate a 16-byte cryptographically random salt
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{hashed}"


def verify_password(stored, password):
    """
    Verify a password against a stored "salt:hash" entry.
    Splits out the salt, hashes the input with it, then compares.
    """
    salt, hashed = stored.split(":")
    return hashlib.sha256((salt + password).encode()).hexdigest() == hashed

def create_user(username, password, display_name, role="analyst"):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, display_name, role) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), display_name, role)
        )
        conn.commit()
        uid = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]
        conn.close()
        return uid
    except sqlite3.IntegrityError:
        conn.close()
        return None

def get_user_by_username(username):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_user_by_id(user_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def save_result(user_id, alert_id, verdict_given, action_given,
                is_verdict_correct, is_action_correct, time_spent=0, quiz_score=0, quiz_total=0):
    conn = get_db()
    both = 1 if is_verdict_correct and is_action_correct else 0
    conn.execute(
        """INSERT INTO results (user_id, alert_id, verdict_given, action_given,
           is_verdict_correct, is_action_correct, is_both_correct,
           time_spent_seconds, quiz_score, quiz_total) VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (user_id, alert_id, verdict_given, action_given,
         int(is_verdict_correct), int(is_action_correct), both,
         time_spent, quiz_score, quiz_total)
    )
    conn.commit()
    conn.close()

def get_user_stats(user_id):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM results WHERE user_id = ? ORDER BY created_at DESC", (user_id,)
    ).fetchall()
    conn.close()
    results = [dict(r) for r in rows]
    total = len(results)
    correct = sum(1 for r in results if r["is_both_correct"])
    total_time = sum(r["time_spent_seconds"] for r in results)
    qc = sum(r["quiz_score"] for r in results)
    qt = sum(r["quiz_total"] for r in results)
    return {
        "total_attempts": total,
        "correct_decisions": correct,
        "incorrect_decisions": total - correct,
        "accuracy": round((correct / total * 100), 1) if total > 0 else 0,
        "total_time": total_time,
        "avg_time": round(total_time / total) if total > 0 else 0,
        "quiz_correct": qc,
        "quiz_total": qt,
        "quiz_accuracy": round((qc / qt * 100), 1) if qt > 0 else 0,
        "results": results,
    }

def get_leaderboard():
    """
    Return all users ranked by:
    1. Number of correct decisions (descending)
    2. Average response time (ascending — faster is better)
    Only users with at least one attempt are included.
    """
    conn = get_db()
    rows = conn.execute("""
        SELECT u.display_name, u.username,
               COUNT(r.id) as total_attempts,
               SUM(r.is_both_correct) as correct,
               ROUND(AVG(r.time_spent_seconds)) as avg_time,
               SUM(r.quiz_score) as quiz_score
        FROM users u
        LEFT JOIN results r ON u.id = r.user_id
        GROUP BY u.id
        HAVING total_attempts > 0
        ORDER BY correct DESC, avg_time ASC
    """).fetchall()
    conn.close()
    board = []
    for r in rows:
        d = dict(r)
        d["accuracy"] = round((d["correct"] / d["total_attempts"] * 100), 1) if d["total_attempts"] > 0 else 0
        board.append(d)
    return board

def get_user_alert_history(user_id):
    conn = get_db()
    rows = conn.execute("""
        SELECT r.*, a.title as alert_title, a.severity, a.difficulty
        FROM results r JOIN alerts a ON r.alert_id = a.id
        WHERE r.user_id = ?
        ORDER BY r.created_at DESC
    """, (user_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


class Alert:
    """
    Represents a single alert combined with the current user's state.
    user_state is optional; if provided, the user's individual
    status/verdict/assignee override the defaults.
    """
    def __init__(self, row, user_state=None):
        self.id = row['id']
        self.title = row['title']
        self.description = row['description']
        self.severity = row['severity']
        self.alert_type = row['alert_type']
        try:
            self.difficulty = row['difficulty'] or 'Medium'
        except (IndexError, KeyError):
            self.difficulty = 'Medium'
        self.source_ip = row['source_ip']
        self.destination_ip = row['destination_ip']
        self.file_hash = row['file_hash']
        self.cve_id = row['cve_id']
        self.mitre_tactic = row['mitre_tactic']
        self.mitre_technique_id = row['mitre_technique_id']
        self.mitre_technique_name = row['mitre_technique_name']
        # Per-user state if provided, else defaults
        if user_state:
            self.status = user_state.get('status', 'Awaiting Action')
            self.assignee = user_state.get('assignee', 'None')
            self.verdict = user_state.get('verdict', 'None')
            self.analyst_comment = user_state.get('analyst_comment', '')
        else:
            self.status = 'Awaiting Action'
            self.assignee = 'None'
            self.verdict = 'None'
            self.analyst_comment = ''
        self.details = row['details']
        self.correct_verdict = row['correct_verdict']
        self.correct_action = row['correct_action']
        self.correct_explanation = row['correct_explanation']
        self.questions = row['questions']
        self.created_at = datetime.strptime(row['created_at'], '%Y-%m-%d %H:%M:%S') if isinstance(row['created_at'], str) else row['created_at']
        self.updated_at = datetime.strptime(row['updated_at'], '%Y-%m-%d %H:%M:%S') if isinstance(row['updated_at'], str) and row['updated_at'] else self.created_at

    # ----- Bootstrap badge colours -----
    def severity_color(self):
        """Bootstrap colour class based on severity."""
        return {'Critical': 'danger', 'High': 'warning', 'Medium': 'info', 'Low': 'secondary'}.get(self.severity, 'secondary')
    def status_color(self):
        """Bootstrap colour class based on status."""
        return {'Awaiting Action': 'danger', 'In Progress': 'warning', 'Closed': 'success'}.get(self.status, 'secondary')
    def verdict_color(self):
        """Bootstrap colour class based on verdict."""
        return {'True Positive': 'success', 'False Positive': 'danger', 'None': 'secondary'}.get(self.verdict, 'secondary')
    def difficulty_color(self):
        """Bootstrap colour class based on difficulty level."""
        return {'Easy': 'success', 'Medium': 'warning', 'Hard': 'danger'}.get(self.difficulty, 'secondary')


def get_all_alerts(severity=None, status=None, difficulty=None, user_id=None):
    conn = get_db()
    query = 'SELECT * FROM alerts'
    params = []
    conditions = []
    if severity:
        conditions.append('severity = ?')
        params.append(severity)
    if difficulty:
        conditions.append('difficulty = ?')
        params.append(difficulty)
    if conditions:
        query += ' WHERE ' + ' AND '.join(conditions)
    query += ' ORDER BY created_at DESC'
    rows = conn.execute(query, params).fetchall()
    conn.close()
    # Apply per-user state
    user_states = get_user_alert_states(user_id) if user_id else {}
    alerts = [Alert(row, user_states.get(row['id'])) for row in rows]
    # Status filter applied AFTER user state (because status is per-user)
    if status:
        alerts = [a for a in alerts if a.status == status]
    return alerts

def get_alert_by_id(alert_id, user_id=None):
    conn = get_db()
    row = conn.execute('SELECT * FROM alerts WHERE id = ?', (alert_id,)).fetchone()
    conn.close()
    if not row:
        return None
    user_state = get_user_alert_state(user_id, alert_id) if user_id else None
    return Alert(row, user_state)

def update_alert_field(alert_id, **fields):
    """Legacy: updates the alerts table directly. Kept for backward compat."""
    conn = get_db()
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    for key, value in fields.items():
        conn.execute(f'UPDATE alerts SET {key} = ?, updated_at = ? WHERE id = ?', (value, now, alert_id))
    conn.commit()
    conn.close()

def get_alert_count():
    conn = get_db()
    count = conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
    conn.close()
    return count

def get_critical_high_alerts(limit=8, user_id=None):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM alerts WHERE severity IN ('Critical', 'High') ORDER BY created_at DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    user_states = get_user_alert_states(user_id) if user_id else {}
    return [Alert(r, user_states.get(r['id'])) for r in rows]


# ============ PER-USER ALERT STATE ============

def get_user_alert_state(user_id, alert_id):
    """Get the user's current state on a specific alert."""
    conn = get_db()
    # Latest assignment/decision for this user on this alert
    row = conn.execute("""
        SELECT * FROM user_alert_state
        WHERE user_id = ? AND alert_id = ?
    """, (user_id, alert_id)).fetchone()
    conn.close()
    return dict(row) if row else None


def set_user_alert_state(user_id, alert_id, **fields):
    """Insert or update a user's alert state."""
    conn = get_db()
    existing = conn.execute(
        "SELECT id FROM user_alert_state WHERE user_id = ? AND alert_id = ?",
        (user_id, alert_id)
    ).fetchone()
    if existing:
        sets = ", ".join(f"{k} = ?" for k in fields.keys())
        values = list(fields.values()) + [user_id, alert_id]
        conn.execute(
            f"UPDATE user_alert_state SET {sets} WHERE user_id = ? AND alert_id = ?",
            values
        )
    else:
        cols = ", ".join(["user_id", "alert_id"] + list(fields.keys()))
        placeholders = ", ".join(["?"] * (2 + len(fields)))
        values = [user_id, alert_id] + list(fields.values())
        conn.execute(
            f"INSERT INTO user_alert_state ({cols}) VALUES ({placeholders})",
            values
        )
    conn.commit()
    conn.close()


def reset_user_alert_state(user_id, alert_id):
    """Remove a user's state on a specific alert (full reopen)."""
    conn = get_db()
    conn.execute(
        "DELETE FROM user_alert_state WHERE user_id = ? AND alert_id = ?",
        (user_id, alert_id)
    )
    conn.commit()
    conn.close()


def reset_all_user_states(user_id):
    """Remove all alert states for a user (Reset All button)."""
    conn = get_db()
    conn.execute("DELETE FROM user_alert_state WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()


def get_user_alert_states(user_id):
    """Get all alert states for a user as dict {alert_id: state_dict}."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM user_alert_state WHERE user_id = ?", (user_id,)
    ).fetchall()
    conn.close()
    return {r["alert_id"]: dict(r) for r in rows}
