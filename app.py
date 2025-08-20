# app.py — full booking app with calendar/email/SMS + resilient homepage (Render-safe)
import os, sys
from pathlib import Path
from datetime import datetime, date, timedelta
from urllib.parse import quote

from flask import (
    Flask, render_template, render_template_string, request,
    redirect, url_for, flash, session, Response, jsonify
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
from twilio.rest import Client as TwilioClient

# Google Calendar (uses token.json on server; skips OAuth flow)
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

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

# --- SELF-HEALING TEMPLATES (prevents TemplateNotFound on Render) ---
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
    if not (sid and token and from_number and to_number):
        print(f"[SMS DRY-RUN] To: {to_number} | {body}")
        return
    client = TwilioClient(sid, token)
    client.messages.create(to=to_number, from_=from_number, body=body)

SCOPES = ["https://www.googleapis.com/auth/calendar"]

def _get_google_creds():
    """
    Server-safe creds: use token.json if present; refresh if needed.
    Do NOT run OAuth browser flow on Render (no UI) — just skip if token missing.
    To allow local OAuth, run on your machine to generate token.json, then upload to Render Secret Files.
    """
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
    if not calendar_id:
        print("[Calendar] GOOGLE_CALENDAR_ID missing. Skipping calendar update.")
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
    if not (calendar_id and event_id):
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
# Ensure DB exists (Render-safe)
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

@app.route("/calendar")
def calendar_view():
    # Prefer a dedicated embed ID if you have one; else fall back to GOOGLE_CALENDAR_ID
    cal_id = os.getenv("GOOGLE_CALENDAR_EMBED_ID") or os.getenv("GOOGLE_CALENDAR_ID")
    embed_src = None
    if cal_id:
        # Embed URL docs: https://support.google.com/calendar/answer/41207
        embed_src = (
            "https://calendar.google.com/calendar/embed"
            f"?src={quote(cal_id)}"
            "&ctz=America%2FNew_York"
            "&mode=MONTH"              # MONTH | WEEK | AGENDA
            "&showPrint=0&showTitle=0" # tidy look
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

@app.route("/admin/requests")
def admin_requests():
    if not is_admin():
        return redirect(url_for("admin_login"))
    dues_first = case((Member.member_type == "due", 0), else_=1)
    pending = (db.session.query(BookingRequest)
               .join(Member)
               .filter(BookingRequest.status == "pending")
               .order_by(dues_first.asc(), BookingRequest.created_at.asc())
               .all())
    approved = (db.session.query(BookingRequest)
                .join(Member)
                .filter(BookingRequest.status == "approved")
                .order_by(dues_first.asc(), BookingRequest.start_date.asc())
                .all())
    denied = (db.session.query(BookingRequest)
              .join(Member)
              .filter(BookingRequest.status == "denied")
              .order_by(BookingRequest.created_at.desc())
              .all())
    return render_template("admin_requests.html",
                           pending
