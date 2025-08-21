# app.py — Lake House bookings (Render-safe, single-file, self-healing templates)
import os, sys
from pathlib import Path
from datetime import datetime, date, timedelta
from urllib.parse import quote

from flask import (
    Flask, render_template, render_template_string, request,
    redirect, url_for, flash, session, Response, jsonify, make_response
)
from jinja2 import TemplateNotFound

from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, DateField, TextAreaField, SubmitField, BooleanField, PasswordField
from wtforms.validators import DataRequired, Email, Length
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import case

# Notifications
import smtplib
from email.mime.text import MIMEText

# Twilio (optional; DRY-RUN if missing)
try:
    from twilio.rest import Client as TwilioClient
except Exception:  # pragma: no cover
    TwilioClient = None

# Google Calendar (optional; DRY-RUN if missing)
try:
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build
    from google.auth.transport.requests import Request
    GOOGLE_OK = True
except Exception:  # pragma: no cover
    GOOGLE_OK = False

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"

app = Flask(__name__, template_folder=str(TEMPLATES_DIR))
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///lakehouse.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# -----------------------------
# Models
# -----------------------------
class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(32), nullable=True)
    member_type = db.Column(db.String(32), nullable=False, default="non_due")  # "due" or "non_due"

class BookingRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('member.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(16), nullable=False, default="pending")  # pending/approved/denied/cancelled
    calendar_event_id = db.Column(db.String(128), nullable=True)
    member = db.relationship("Member", backref=db.backref("requests", lazy=True))

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(32), nullable=False)  # approve/deny/cancel/create
    request_id = db.Column(db.Integer, db.ForeignKey('booking_request.id'), nullable=True)
    admin_email = db.Column(db.String(255), nullable=True)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# -----------------------------
# Forms
# -----------------------------
class RequestForm(FlaskForm):
    name = StringField("Your Name", validators=[DataRequired(), Length(max=120)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    phone = StringField("Phone (optional)")
    member_type = SelectField("Membership Type", choices=[
        ("due", "Due-paying member"),
        ("non_due", "Non due-paying member")
    ], validators=[DataRequired()])
    start_date = DateField("Start Date", validators=[DataRequired()], format="%Y-%m-%d")
    end_date = DateField("End Date", validators=[DataRequired()], format="%Y-%m-%d")
    notes = TextAreaField("Notes (optional)")
    subscribe_sms = BooleanField("Send me SMS updates")
    submit = SubmitField("Submit Request")

class AdminLoginForm(FlaskForm):
    email = StringField("Admin Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign in")

# --- SELF-HEALING TEMPLATES ---
DEFAULT_TEMPLATES = {
    "base.html": """<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Lake House Bookings</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
  <style>
    .badge { padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.75rem; }
    .badge.due { background: #0ea5e9; color: white; }
    .badge.non_due { background: #94a3b8; color: white; }
    .tag { font-size: 0.75rem; padding: 0.15rem 0.35rem; border-radius: 999px; background: #e2e8f0; color:#334155; }
    code { font-size: 0.8rem; }
  </style>
</head>
<body>
  <main class="container">
    <nav>
      <ul><li><strong>Lake House Bookings</strong></li></ul>
      <ul>
        <li><a href="{{ url_for('home') }}">Request</a></li>
        <li><a href="{{ url_for('calendar_view') }}">Calendar</a></li>
        <li><a href="{{ url_for('calendar_ics') }}">ICS feed</a></li>
        {% if session.get('is_admin') %}
          <li><a href="{{ url_for('admin_requests') }}">Admin</a></li>
          <li><a href="{{ url_for('admin_logout') }}">Logout</a></li>
        {% else %}
          <li><a href="{{ url_for('admin_login') }}">Admin</a></li>
        {% endif %}
      </ul>
    </nav>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        <div>
          {% for category, message in messages %}
            <article class="{{ category }}">{{ message }}</article>
          {% endfor %}
        </div>
      {% endif %}
    {% endwith %}
    {% block content %}{% endblock %}
    <footer style="margin-top:3rem; font-size:0.9rem; color:#64748b;">
      Built with Flask • Conflict detection • Dues priority • Audit log • ICS feed
    </footer>
  </main>
</body></html>""",

    "home.html": """{% extends "base.html" %}
{% block content %}
<h2>Request time at the Lake House</h2>
<form method="POST">
  {{ form.hidden_tag() }}
  <div class="grid">
    <label>{{ form.name.label }} {{ form.name(size=32) }}</label>
    <label>{{ form.email.label }} {{ form.email(size=32) }}</label>
    <label>{{ form.phone.label }} {{ form.phone(size=20) }}</label>
    <label>{{ form.member_type.label }} {{ form.member_type() }}</label>
    <label>{{ form.start_date.label }} {{ form.start_date() }}</label>
    <label>{{ form.end_date.label }} {{ form.end_date() }}</label>
  </div>
  <label>{{ form.notes.label }} {{ form.notes(rows=3) }}</label>
  <label>{{ form.subscribe_sms() }} {{ form.subscribe_sms.label }}</label>
  <button type="submit">Submit Request</button>
</form>
{% endblock %}""",

    "admin_login.html": """{% extends "base.html" %}
{% block content %}
<h2>Admin Login</h2>
{% if form.errors %}
  <article class="warning">
    <strong>Form errors:</strong>
    <ul>
      {% for field, errs in form.errors.items() %}
        {% for e in errs %}<li>{{ field }}: {{ e }}</li>{% endfor %}
      {% endfor %}
    </ul>
  </article>
{% endif %}
<form method="POST">
  {{ form.hidden_tag() }}
  <label>{{ form.email.label }} {{ form.email(size=32) }}</label>
  <label>{{ form.password.label }} {{ form.password(size=32) }}</label>
  <button type="submit">Sign in</button>
</form>
{% endblock %}""",

    "admin_requests.html": """{% extends "base.html" %}
{% block content %}
<h2>Pending Requests</h2>
{% if pending %}
<table role="grid">
  <thead><tr><th>Member</th><th>Dates</th><th>Notes</th><th>Actions</th></tr></thead>
  <tbody>
  {% for r in pending %}
    <tr>
      <td>{{ r.member.name }} ({{ r.member.member_type }})<br><small>{{ r.member.email }}</small></td>
      <td>{{ r.start_date }} → {{ r.end_date }}</td>
      <td>{{ r.notes }}</td>
      <td>
        <form method="POST" action="{{ url_for('approve_request', req_id=r.id) }}" style="display:inline;">
          <button>Approve</button>
        </form>
        <form method="POST" action="{{ url_for('deny_request', req_id=r.id) }}" style="display:inline;">
          <button class="secondary">Deny</button>
        </form>
      </td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% else %}
<p>No pending requests.</p>
{% endif %}

<h2>Approved</h2>
{% if approved %}
<table role="grid">
  <thead><tr><th>Member</th><th>Dates</th><th>Calendar</th><th>Actions</th></tr></thead>
  <tbody>
  {% for r in approved %}
    <tr>
      <td>{{ r.member.name }} ({{ r.member.member_type }})</td>
      <td>{{ r.start_date }} → {{ r.end_date }}</td>
      <td>{% if r.calendar_event_id %}<code>{{ r.calendar_event_id }}</code>{% else %}-{% endif %}</td>
      <td>
        <form method="POST" action="{{ url_for('deny_request', req_id=r.id) }}" style="display:inline;">
          <button class="secondary">Revoke</button>
        </form>
        <form method="POST" action="{{ url_for('cancel_request', req_id=r.id) }}" style="display:inline;">
          <button class="contrast">Cancel</button>
        </form>
      </td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% else %}
<p>No approved bookings.</p>
{% endif %}

<h2>Denied</h2>
{% if denied %}
<table role="grid">
  <thead><tr><th>Member</th><th>Dates</th><th>Notes</th></tr></thead>
  <tbody>
  {% for r in denied %}
    <tr><td>{{ r.member.name }}</td><td>{{ r.start_date }} → {{ r.end_date }}</td><td>{{ r.notes }}</td></tr>
  {% endfor %}
  </tbody>
</table>
{% else %}
<p>No denied requests.</p>
{% endif %}
{% endblock %}""",

    "calendar_embed.html": """{% extends "base.html" %}
{% block content %}
<h2>Lake House Calendar</h2>
{% if embed_src %}
  <iframe
    src="{{ embed_src }}"
    style="border:0; width:100%; height:75vh;"
    frameborder="0" scrolling="no">
  </iframe>
  <p style="margin-top:0.75rem;">
    Need an ICS? <a href="{{ url_for('calendar_ics') }}">Subscribe to the iCal feed</a>.
  </p>
{% else %}
  <article class="warning">
    <strong>Calendar not configured.</strong>
    <p>Set <code>GOOGLE_CALENDAR_EMBED_ID</code> (recommended) or <code>GOOGLE_CALENDAR_ID</code> in Render, then redeploy.</p>
  </article>
{% endif %}
{% endblock %}""",
}

def _ensure_templates_present():
    try:
        TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
        for name, content in DEFAULT_TEMPLATES.items():
            p = TEMPLATES_DIR / name
            if not p.exists():
                p.write_text(content, encoding="utf-8")
                app.logger.info(f"[bootstrap] wrote missing template: {p}")
    except Exception as e:
        app.logger.error(f"[bootstrap] failed creating templates: {e}")

_ensure_templates_present()
# --- END SELF-HEALING TEMPLATES ---

# -----------------------------
# Helpers: Email, SMS, Calendar
# -----------------------------
def send_email(to_email, subject, body):
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = os.getenv("SMTP_PORT")
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    email_from = os.getenv("EMAIL_FROM", "no-reply@lakehouse.local")
    if not (smtp_host and smtp_port and smtp_user and smtp_pass):
        print(f"[EMAIL DRY-RUN] To: {to_email} | Subject: {subject}\n{body}")
        return
    msg = MIMEText(body, "plain")
    msg["Subject"] = subject
    msg["From"] = email_from
    msg["To"] = to_email
    with smtplib.SMTP(smtp_host, int(smtp_port)) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)

def send_sms(to_number, body):
    sid = os.getenv("TWILIO_ACCOUNT_SID")
    token = os.getenv("TWILIO_AUTH_TOKEN")
    from_number = os.getenv("TWILIO_FROM_NUMBER")
    if not (sid and token and from_number and to_number and TwilioClient):
        print(f"[SMS DRY-RUN] To: {to_number} | {body}")
        return
    client = TwilioClient(sid, token)
    client.messages.create(to=to_number, from_=from_number, body=body)

SCOPES = ["https://www.googleapis.com/auth/calendar"]

def _get_google_creds():
    """
    Server-safe creds: use token.json if present; refresh if needed.
    Do NOT run OAuth browser flow on Render — just skip if token missing.
    Locally, generate token.json and upload it to Render Secret Files.
    """
    if not GOOGLE_OK:
        print("[Calendar] google libraries not installed; skipping.")
        return None
    token_path = BASE_DIR / "token.json"
    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)
        if not creds.valid:
            if creds.refresh_token:
                try:
                    creds.refresh(Request())
                    with open(token_path, "w") as f:
                        f.write(creds.to_json())
                except Exception as e:
                    print(f"[Calendar] Refresh failed: {e}")
                    return None
        return creds
    print("[Calendar] token.json not found; skipping calendar sync on server.")
    return None

def add_event_to_calendar(summary, start_date, end_date, description=""):
    calendar_id = os.getenv("GOOGLE_CALENDAR_ID")
    if not (calendar_id and GOOGLE_OK):
        print("[Calendar] Missing GOOGLE_CALENDAR_ID or google libs; skipping.")
        return None
    creds = _get_google_creds()
    if not creds:
        return None
    service = build("calendar", "v3", credentials=creds)
    event_body = {
        "summary": summary,
        "description": description,
        "start": {"date": start_date.isoformat()},  # all-day
        "end": {"date": (end_date + timedelta(days=1)).isoformat()},  # exclusive end
    }
    event = service.events().insert(calendarId=calendar_id, body=event_body).execute()
    return event.get("id")

def remove_event_from_calendar(event_id):
    calendar_id = os.getenv("GOOGLE_CALENDAR_ID")
    if not (calendar_id and event_id and GOOGLE_OK):
        return
    creds = _get_google_creds()
    if not creds:
        return
    service = build("calendar", "v3", credentials=creds)
    try:
        service.events().delete(calendarId=calendar_id, eventId=event_id).execute()
    except Exception as e:
        print(f"[Calendar] Failed to delete event: {e}")

# -----------------------------
# Business rules
# -----------------------------
def ranges_overlap(a_start, a_end, b_start, b_end):
    return not (a_end < b_start or b_end < a_start)

def find_conflicts(start_date, end_date, exclude_request_id=None):
    q = BookingRequest.query.filter(BookingRequest.status == "approved")
    if exclude_request_id:
        q = q.filter(BookingRequest.id != exclude_request_id)
    return [r for r in q.all() if ranges_overlap(start_date, end_date, r.start_date, r.end_date)]

def is_admin():
    return bool(session.get("is_admin"))

def current_admin_email():
    return os.getenv("ADMIN_EMAIL") if is_admin() else None

def _log(action, request_id, details=""):
    db.session.add(AuditLog(action=action, request_id=request_id, admin_email=current_admin_email(), details=details))
    db.session.commit()

def _notify_status(br: BookingRequest):
    member = br.member
    subj = f"Lake House request {br.status.upper()}: {br.start_date} - {br.end_date}"
    body = f"Hi {member.name},\n\nYour request for {br.start_date} to {br.end_date} has been {br.status}."
    if br.status == "approved":
        body += "\nWe added it to the lake house calendar."
    elif br.status == "denied":
        body += "\nPlease contact the admin with any questions."
    send_email(member.email, subj, body)
    if member.phone:
        send_sms(member.phone, f"Lake House: your request {br.status} for {br.start_date} - {br.end_date}.")

# -----------------------------
# Ensure DB exists
# -----------------------------
@app.before_request
def _ensure_db():
    if not getattr(app, "_db_inited", False):
        with app.app_context():
            db.create_all()
        app._db_inited = True

# -----------------------------
# Routes
# -----------------------------
@app.route("/", methods=["GET", "POST"])
def home():
    if (TEMPLATES_DIR / "home.html").exists():
        form = RequestForm()
        if form.validate_on_submit():
            member = Member.query.filter_by(email=form.email.data.strip()).first()
            if not member:
                member = Member(
                    name=form.name.data.strip(),
                    email=form.email.data.strip(),
                    phone=form.phone.data.strip() if form.phone.data else None,
                    member_type=form.member_type.data,
                )
                db.session.add(member)
                db.session.flush()
            else:
                member.name = form.name.data.strip()
                member.phone = form.phone.data.strip() if form.phone.data else member.phone
                member.member_type = form.member_type.data

            br = BookingRequest(
                member_id=member.id,
                start_date=form.start_date.data,
                end_date=form.end_date.data,
                notes=form.notes.data
            )
            db.session.add(br)
            db.session.commit()

            conflicts = find_conflicts(br.start_date, br.end_date)
            if conflicts:
                flash("Heads up: those dates overlap with an approved booking. Admin will review.", "warning")

            # notify admin + requester
            send_email(
                os.getenv("ADMIN_EMAIL", member.email),
                "New Lake House Booking Request",
                f"{member.name} ({member.member_type}) requested {br.start_date} - {br.end_date}.\n"
                f"Notes: {br.notes or '(none)'}\nReview: {request.url_root}admin/requests"
            )
            send_email(
                member.email,
                "We received your lake house request",
                f"Hi {member.name},\n\nWe received your request for {br.start_date} to {br.end_date}. "
                "We'll notify you once it's approved or denied.\n\nThanks!"
            )
            if form.subscribe_sms.data and member.phone:
                send_sms(member.phone, f"Lake House: request received for {br.start_date} - {br.end_date}.")

            _log("create", br.id, f"Created by {member.email}")
            flash("Request submitted! You'll receive an email confirmation.", "success")
            return redirect(url_for("home"))
        return render_template("home.html", form=form)

    # fallback inline if template missing
    return render_template_string("""
      <!doctype html><html lang="en"><head><meta charset="utf-8"><title>Lake House</title></head>
      <body>
        <h1>Lake House Bookings</h1>
        <p>✅ App is running, but <code>templates/home.html</code> is missing. Create it and redeploy.</p>
        <p><a href="/_diag">Diagnostics</a></p>
      </body></html>
    """)

# Friendly aliases to home
@app.route("/index")
@app.route("/home")
def index_alias():
    return redirect(url_for("home"), code=302)

# Favicon (avoid noisy 404s)
@app.route("/favicon.ico")
def favicon():
    return ("", 204)

@app.route("/calendar")
def calendar_view():
    # Prefer a dedicated embed ID if you have one; else fall back to GOOGLE_CALENDAR_ID
    cal_id = os.getenv("GOOGLE_CALENDAR_EMBED_ID") or os.getenv("GOOGLE_CALENDAR_ID")
    embed_src = None
    if cal_id:
        embed_src = (
            "https://calendar.google.com/calendar/embed"
            f"?src={quote(cal_id)}"
            "&ctz=America%2FNew_York"
            "&mode=MONTH"
            "&showPrint=0&showTitle=0"
        )
    return render_template("calendar_embed.html", embed_src=embed_src, calendar_id=cal_id)

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    form = AdminLoginForm()
    if request.method == "POST":
        if not form.validate_on_submit():
            flash(f"Form validation failed: {form.errors}", "danger")
        else:
            admin_email = os.getenv("ADMIN_EMAIL", "")
            admin_password = os.getenv("ADMIN_PASSWORD", "")
            ok_email = form.email.data.strip().lower() == admin_email.strip().lower()
            ok_pwd = form.password.data == admin_password
            if ok_email and ok_pwd:
                session["is_admin"] = True
                flash("Welcome, admin!", "success")
                return redirect(url_for("admin_requests"))
            else:
                flash("Invalid credentials.", "danger")
    try:
        return render_template("admin_login.html", form=form)
    except TemplateNotFound:
        app.logger.error("admin_login.html missing; rendering inline fallback")
        return render_template_string("""
          <!doctype html><html><head><meta charset="utf-8">
          <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
          <title>Admin Login (fallback)</title></head><body><main class="container">
          <h2>Admin Login</h2>
          <p style="color:#b91c1c">Template <code>templates/admin_login.html</code> not found; using fallback.</p>
          <form method="POST">
            {{ form.hidden_tag() }}
            <label>{{ form.email.label }} {{ form.email(size=32) }}</label>
            <label>{{ form.password.label }} {{ form.password(size=32) }}</label>
            <button type="submit">Sign in</button>
          </form>
          </main></body></html>
        """, form=form), 200

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("home"))

# Admin requests — FIXED (balanced parentheses)
@app.route("/admin/requests")
def admin_requests():
    if not is_admin():
        return redirect(url_for("admin_login"))

    dues_first = case((Member.member_type == "due", 0), else_=1)

    pending = (
        db.session.query(BookingRequest)
        .join(Member)
        .filter(BookingRequest.status == "pending")
        .order_by(dues_first.asc(), BookingRequest.created_at.asc())
        .all()
    )

    approved = (
        db.session.query(BookingRequest)
        .join(Member)
        .filter(BookingRequest.status == "approved")
        .order_by(dues_first.asc(), BookingRequest.start_date.asc())
        .all()
    )

    denied = (
        db.session.query(BookingRequest)
        .join(Member)
        .filter(BookingRequest.status == "denied")
        .order_by(BookingRequest.created_at.desc())
        .all()
    )

    return render_template(
        "admin_requests.html",
        pending=pending,
        approved=approved,
        denied=denied,
        logs=AuditLog.query.order_by(AuditLog.created_at.desc()).limit(50).all(),
    )

# Admin diagnostics
@app.route("/admin/_diag")
def admin_diag():
    raw = os.getenv("ADMIN_EMAIL", "")
    masked = (raw[:2] + "***" + raw[-2:]) if len(raw) >= 5 else ("***" if raw else "")
    return {
        "has_secret_key": bool(app.config.get("SECRET_KEY")),
        "has_admin_email": bool(os.getenv("ADMIN_EMAIL")),
        "admin_email_masked": masked,
        "has_admin_password": bool(os.getenv("ADMIN_PASSWORD")),
    }, 200

# Files diag
@app.route("/_ls")
def _ls():
    tree = []
    for root, dirs, files in os.walk(".", topdown=True):
        if "/.venv" in root or "/site-packages" in root:
            continue
        tree.append({"root": root, "dirs": sorted(dirs), "files": sorted(files)})
    return {"cwd": os.getcwd(), "tree": tree}, 200

# Route lister
@app.route("/_routes")
def _routes():
    rules = []
    for r in app.url_map.iter_rules():
        methods = ",".join(sorted(m for m in r.methods if m not in ("HEAD","OPTIONS")))
        rules.append({"rule": str(r), "endpoint": r.endpoint, "methods": methods})
    return jsonify(sorted(rules, key=lambda x: x["rule"]))

# Actions
@app.post("/admin/requests/<int:req_id>/approve")
def approve_request(req_id):
    if not is_admin():
        return redirect(url_for("admin_login"))
    br = BookingRequest.query.get_or_404(req_id)
    conflicts = find_conflicts(br.start_date, br.end_date, exclude_request_id=br.id)
    if conflicts:
        conflict_list = ", ".join([f"{c.member.name}({c.start_date}→{c.end_date})" for c in conflicts])
        flash(f"Cannot approve: date conflict with {conflict_list}.", "danger")
        return redirect(url_for("admin_requests"))
    br.status = "approved"
    summary = f"Lake House: {br.member.name} ({br.member.member_type})"
    description = (br.notes or "") + f"\nMember email: {br.member.email}"
    event_id = add_event_to_calendar(summary, br.start_date, br.end_date, description)
    if event_id:
        br.calendar_event_id = event_id
    db.session.commit()
    _notify_status(br)
    _log("approve", br.id, "Approved and synced to calendar")
    flash("Request approved and calendar updated.", "success")
    return redirect(url_for("admin_requests"))

@app.post("/admin/requests/<int:req_id>/deny")
def deny_request(req_id):
    if not is_admin():
        return redirect(url_for("admin_login"))
    br = BookingRequest.query.get_or_404(req_id)
    br.status = "denied"
    if br.calendar_event_id:
        remove_event_from_calendar(br.calendar_event_id)
        br.calendar_event_id = None
    db.session.commit()
    _notify_status(br)
    _log("deny", br.id, "Denied by admin")
    flash("Request denied.", "info")
    return redirect(url_for("admin_requests"))

@app.post("/admin/requests/<int:req_id>/cancel")
def cancel_request(req_id):
    if not is_admin():
        return redirect(url_for("admin_login"))
    br = BookingRequest.query.get_or_404(req_id)
    br.status = "cancelled"
    if br.calendar_event_id:
        remove_event_from_calendar(br.calendar_event_id)
        br.calendar_event_id = None
    db.session.commit()
    _notify_status(br)
    _log("cancel", br.id, "Cancelled by admin")
    flash("Request cancelled and calendar updated.", "warning")
    return redirect(url_for("admin_requests"))

# Public read-only ICS feed
@app.route("/calendar.ics")
def calendar_ics():
    events = (BookingRequest.query
              .filter(BookingRequest.status == "approved")
              .order_by(BookingRequest.start_date.asc())
              .all())
    def esc(s): return (s or "").replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,")
    def fold(line, limit=75):
        if len(line) <= limit: return [line]
        out = []
        while len(line) > limit:
            out.append(line[:limit]); line = " " + line[limit:]
        out.append(line); return out

    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//LakeHouse//Bookings//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
        "X-WR-CALNAME:Lake House Bookings",
    ]
    for r in events:
        uid = f"lakehouse-{r.id}@example.local"
        dtstamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        dtstart = r.start_date.strftime("%Y%m%d")
        dtend = (r.end_date + timedelta(days=1)).strftime("%Y%m%d")
        summary = esc(f"Lake House: {r.member.name} ({r.member.member_type})")
        desc = esc((r.notes or "") + f"\\nMember email: {r.member.email}")
        ev = [
            "BEGIN:VEVENT",
            f"UID:{uid}",
            f"DTSTAMP:{dtstamp}",
            f"DTSTART;VALUE=DATE:{dtstart}",
            f"DTEND;VALUE=DATE:{dtend}",
            f"SUMMARY:{summary}",
            f"DESCRIPTION:{desc}",
            "END:VEVENT",
        ]
        for line in ev: lines.extend(fold(line))
    ics = "\r\n".join(lines + ["END:VCALENDAR"]) + "\r\n"  # CRLF per RFC5545
    return Response(ics, mimetype="text/calendar")

# Friendly 404 with links
@app.errorhandler(404)
def not_found(e):
    html = """
    <!doctype html><html><head>
      <meta charset='utf-8'><title>Not Found</title>
      <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
    </head><body><main class="container">
      <h2>Not Found</h2>
      <p>The page you requested doesn’t exist. Try one of these:</p>
      <ul>
        <li><a href="/">Home</a></li>
        <li><a href="/calendar">Calendar</a></li>
        <li><a href="/admin/login">Admin login</a></li>
        <li><a href="/_diag">Diagnostics</a></li>
        <li><a href="/_routes">Route list</a></li>
      </ul>
    </main></body></html>
    """
    return make_response(html, 404)

# Diagnostics
@app.route("/_diag")
def _diag():
    try:
        return jsonify({
            "cwd": os.getcwd(),
            "python_version": sys.version,
            "base_dir": str(BASE_DIR),
            "template_dir": str(TEMPLATES_DIR),
            "has_templates_dir": TEMPLATES_DIR.is_dir(),
            "templates_list": sorted(p.name for p in TEMPLATES_DIR.glob("*")) if TEMPLATES_DIR.is_dir() else [],
            "files_in_cwd": sorted(os.listdir(".")),
        })
    except Exception as e:
        return {"error": repr(e)}, 500

# Reminders (opt-in: set ENABLE_SCHEDULER=1)
def send_upcoming_reminders():
    today = date.today()
    in_two_days = today + timedelta(days=2)
    upcoming = BookingRequest.query.filter(
        BookingRequest.status == "approved",
        BookingRequest.start_date == in_two_days
    ).all()
    for br in upcoming:
        send_email(
            br.member.email,
            "Lake House reminder",
            f"Hi {br.member.name}, your lake house stay starts on {br.start_date}. Enjoy!"
        )
        if br.member.phone:
            send_sms(br.member.phone, f"Reminder: your lake house stay starts on {br.start_date}.")

if os.getenv("ENABLE_SCHEDULER", "0") == "1":
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(send_upcoming_reminders, "cron", hour=9, minute=0)
    scheduler.start()

@app.cli.command("init-db")
def init_db():
    db.create_all()
    print("Database initialized.")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000)
