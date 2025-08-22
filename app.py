# app.py — Lake House bookings (Flatpickr calendar fixed, sign-out visible, end-day overlap allowed)
import os, sys, json, csv, socket
from io import StringIO
from pathlib import Path
from datetime import datetime, date, timedelta
from urllib.parse import quote

from flask import (
    Flask, render_template, render_template_string, request,
    redirect, url_for, flash, session, Response, jsonify, make_response
)
from jinja2 import TemplateNotFound

from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, DateField, TextAreaField, SubmitField, BooleanField, PasswordField
from wtforms.validators import DataRequired, Email, Length
from sqlalchemy import case, text
from werkzeug.security import generate_password_hash, check_password_hash

# Notifications (SMTP)
import smtplib
from email.mime.text import MIMEText

# Twilio (optional; DRY-RUN if missing)
try:
    from twilio.rest import Client as TwilioClient
except Exception:
    TwilioClient = None

# Google Calendar (optional; DRY-RUN if missing)
try:
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build
    from google.auth.transport.requests import Request
    GOOGLE_OK = True
except Exception:
    GOOGLE_OK = False

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"

app = Flask(__name__, template_folder=str(TEMPLATES_DIR))
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-secret")
# For Render persistent disk use sqlite:////var/data/lakehouse.db
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI", "sqlite:///lakehouse.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# -----------------------------
# Models
# -----------------------------
class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    phone = db.Column(db.String(32), nullable=True)
    member_type = db.Column(db.String(32), nullable=False, default="non_due")  # "due" or "non_due"
    password_hash = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return bool(self.password_hash) and check_password_hash(self.password_hash, password)


class BookingRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('member.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)  # stored as inclusive, but we TREAT end-day as exclusive in logic
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


class DataTransaction(db.Model):
    __tablename__ = "data_transaction"
    id = db.Column(db.Integer, primary_key=True)
    kind = db.Column(db.String(40), nullable=False)      # "email","sms","gcal.insert","gcal.delete"
    status = db.Column(db.String(20), nullable=False)    # "success","error","skip"
    booking_request_id = db.Column(db.Integer, db.ForeignKey('booking_request.id'))
    member_id = db.Column(db.Integer, db.ForeignKey('member.id'))
    target = db.Column(db.String(255))
    meta_json = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    booking_request = db.relationship("BookingRequest", lazy=True)
    member = db.relationship("Member", lazy=True)


class BookingRequestHistory(db.Model):
    __tablename__ = "booking_request_history"
    id = db.Column(db.Integer, primary_key=True)
    booking_request_id = db.Column(db.Integer, db.ForeignKey('booking_request.id'), nullable=False)
    at = db.Column(db.DateTime, default=datetime.utcnow)
    admin_email = db.Column(db.String(255))
    status = db.Column(db.String(16), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    notes = db.Column(db.Text)
    calendar_event_id = db.Column(db.String(128))

    booking_request = db.relationship("BookingRequest", lazy=True)

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
    # We'll force these to text inputs in the template so Flatpickr renders
    start_date = DateField("Start Date", validators=[DataRequired()], format="%Y-%m-%d")
    end_date = DateField("End Date", validators=[DataRequired()], format="%Y-%m-%d")
    notes = TextAreaField("Notes (optional)")
    subscribe_sms = BooleanField("Send me SMS updates")
    submit = SubmitField("Submit Request")


class AdminLoginForm(FlaskForm):
    email = StringField("Admin Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign in")


class SigninForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign in")


class SignupForm(FlaskForm):
    name = StringField("Full name", validators=[DataRequired(), Length(max=120)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    phone = StringField("Phone (optional)")
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Create account")

# -----------------------------
# Self-healing templates (Flatpickr + modern summer lake vibe)
# -----------------------------
DEFAULT_TEMPLATES = {
    # include a version marker so we can detect/refresh if needed
    "base.html": r"""<!-- LAKEHOUSE_BASE_V3 -->
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{{ title or 'Lake House' }}</title>

  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr@4.6.13/dist/flatpickr.min.css">

  <style>
    :root{
      --lake-blue:#3aa4c4; --pine:#1b3a3a; --sand:#f9f6ef; --sun:#ffd166; --text:#0f172a;
    }
    body{ background: linear-gradient(180deg, var(--sand) 0%, #ffffff 80%); color: var(--text); }
    nav{ background: linear-gradient(90deg, var(--lake-blue), #7fd3e7); border-radius: 16px; padding: .75rem 1rem; }
    nav a{ color:#083344; font-weight:600; }
    .brand{ display:flex; gap:.5rem; align-items:center; font-weight:800; color:#053b4a;}
    .brand .dot{ width:10px; height:10px; border-radius:999px; background:var(--sun); box-shadow:0 0 0 4px rgba(255,209,102,.35);}
    .card{ border-radius: 16px; box-shadow: 0 8px 24px rgba(0,0,0,.06); }
    .btn-primary{ background: var(--lake-blue); border:none; }
    .badge{ padding:.2rem .45rem; border-radius:999px; font-size:.75rem; background:#e2f6fb; color:#0b4a5a; }
    .tag{ padding:.15rem .4rem; border-radius:999px; background:#eef2f7; color:#475569; font-size:.75rem;}
    footer{ color:#64748b; font-size:.9rem; }
    .flatpickr-day.disabled,
    .flatpickr-day.disabled:hover{
      background:#f1f5f9;
      color:#94a3b8 !important;
      cursor:not-allowed;
      text-decoration: line-through;
    }
  </style>
</head>
<body>
  <main class="container">
    <nav>
      <ul>
        <li class="brand"><span class="dot"></span>Lake House Bookings</li>
      </ul>
      <ul>
        {% if session.get('user_member_id') %}
          <li><a href="{{ url_for('dashboard') }}">Dashboard</a></li>
          <li><a href="{{ url_for('request_booking') }}">New request</a></li>
          <li><a href="{{ url_for('signout') }}">Sign out</a></li>
        {% else %}
          <li><a href="{{ url_for('signin') }}">Sign in</a></li>
          <li><a href="{{ url_for('signup') }}">Create account</a></li>
        {% endif %}
        {% if session.get('is_admin') %}
          <li><a href="{{ url_for('admin_requests') }}">Admin</a></li>
          <li><a href="{{ url_for('admin_logout') }}">Admin logout</a></li>
        {% else %}
          <li><a href="{{ url_for('admin_login') }}">Admin</a></li>
        {% endif %}
      </ul>
    </nav>

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        <div style="margin-top:1rem">
          {% for category, message in messages %}
            <article class="{{ category }}">{{ message }}</article>
          {% endfor %}
        </div>
      {% endif %}
    {% endwith %}

    {% block content %}{% endblock %}

    <footer style="margin-top:3rem">
      Built with Flask • Conflict detection • ICS feed • Accounts
    </footer>
  </main>

  <!-- Flatpickr -->
  <script src="https://cdn.jsdelivr.net/npm/flatpickr@4.6.13/dist/flatpickr.min.js"></script>
  <script>
    // Calendar initializer — blocks interior booked days, allows end-day overlap
    async function initLakeDatepickers() {
      const pickers = document.querySelectorAll("input.datepicker");
      if (!pickers.length) return;

      let blocked = [];
      try {
        const res = await fetch("{{ url_for('api_booked_dates') }}", {cache:"no-store"});
        blocked = await res.json();
      } catch (e) {
        console.warn("Failed to load blocked dates", e);
      }
      const blockedSet = new Set(blocked);

      function isBlocked(date){
        const iso = date.toISOString().slice(0,10);
        return blockedSet.has(iso);
      }

      function onChangeCheck(selDates, _dateStr, instance){
        if (!selDates.length) return;
        const iso = selDates[0].toISOString().slice(0,10);
        if (blockedSet.has(iso)) {
          alert("That date is already booked (interior day). Please pick another date.");
          instance.clear();
        }
      }

      const opts = {
        dateFormat: "Y-m-d",
        minDate: "today",
        disable: [isBlocked],
        onChange: onChangeCheck
      };

      pickers.forEach(el => {
        // Ensure text type for Flatpickr (avoid native datepicker override)
        el.setAttribute("type","text");
        // In case of server-side render, default or restore value is respected
        el._fp = flatpickr(el, opts);
      });

      // Cross-field checks: end > start and interior overlap guard
      const s = document.querySelector("input[name='start_date']");
      const e = document.querySelector("input[name='end_date']");
      function enforceRange(){
        const sv = s && s.value ? new Date(s.value) : null;
        const ev = e && e.value ? new Date(e.value) : null;
        if (sv && ev && ev <= sv) {
          alert("End date must be AFTER start date.");
          e.value = "";
          if (e._fp) e._fp.clear();
        }
      }
      if (s) s.addEventListener("change", enforceRange);
      if (e) e.addEventListener("change", enforceRange);

      // Prevent submit if any interior day in [start, end) is blocked
      const form = document.querySelector("form[data-validate='booking']");
      if (form) {
        form.addEventListener("submit", (evt) => {
          const sv = s && s.value ? new Date(s.value) : null;
          const ev = e && e.value ? new Date(e.value) : null;
          if (!sv || !ev) return; // server will also validate
          if (ev <= sv) {
            alert("End date must be AFTER start date.");
            evt.preventDefault();
            return;
          }
          let cur = new Date(s.value);
          const end = new Date(e.value);
          while (cur < end) { // end-exclusive
            const iso = cur.toISOString().slice(0,10);
            if (blockedSet.has(iso)) {
              alert("Your selection overlaps with an already booked date (" + iso + "). Please choose different dates.");
              evt.preventDefault();
              return;
            }
            cur.setDate(cur.getDate()+1);
          }
        });
      }
    }
    document.addEventListener("DOMContentLoaded", initLakeDatepickers);
  </script>
</body>
</html>""",

    "landing.html": r"""{% extends "base.html" %}
{% block content %}
<section class="card" style="padding:1.25rem; margin-top:1.25rem;">
  <h2>Welcome to the Lake House</h2>
  <p>Sign in to see your bookings, or create a new request.</p>
  <div class="grid">
    <a class="btn-primary" href="{{ url_for('signin') }}">Sign in</a>
    <a class="secondary" href="{{ url_for('signup') }}">Create account</a>
  </div>
</section>
{% endblock %}""",

    "auth_signin.html": r"""{% extends "base.html" %}
{% block content %}
<h2>Sign in</h2>
<form method="POST" class="card" style="padding:1rem;">
  {{ form.hidden_tag() }}
  <label>{{ form.email.label }} {{ form.email(size=32) }}</label>
  <label>{{ form.password.label }} {{ form.password(size=32) }}</label>
  <button class="btn-primary" type="submit">Sign in</button>
</form>
<p>No account? <a href="{{ url_for('signup') }}">Create one</a></p>
{% endblock %}""",

    "auth_signup.html": r"""{% extends "base.html" %}
{% block content %}
<h2>Create account</h2>
<form method="POST" class="card" style="padding:1rem;">
  {{ form.hidden_tag() }}
  <label>{{ form.name.label }} {{ form.name(size=32) }}</label>
  <label>{{ form.email.label }} {{ form.email(size=32) }}</label>
  <label>{{ form.phone.label }} {{ form.phone(size=20) }}</label>
  <label>{{ form.password.label }} {{ form.password(size=32) }}</label>
  <button class="btn-primary" type="submit">Create account</button>
</form>
<p>Already have an account? <a href="{{ url_for('signin') }}">Sign in</a></p>
{% endblock %}""",

    "dashboard.html": r"""{% extends "base.html" %}
{% block content %}
<section class="card" style="padding:1rem; margin-top:1rem;">
  <h2>Hello{{ ' ' + me.name if me else '' }} 👋</h2>
  <p class="tag">Your bookings</p>
  <h3>Upcoming (approved)</h3>
  {% if upcoming %}
  <table role="grid">
    <thead><tr><th>Dates</th><th>Notes</th></tr></thead>
    <tbody>
      {% for r in upcoming %}
        <tr><td>{{ r.start_date }} → {{ r.end_date }}</td><td>{{ r.notes or '' }}</td></tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}<p>No upcoming bookings.</p>{% endif %}

  <h3>Pending</h3>
  {% if pending %}
  <table role="grid">
    <thead><tr><th>Dates</th><th>Notes</th><th>Created</th></tr></thead>
    <tbody>
      {% for r in pending %}
        <tr>
          <td>{{ r.start_date }} → {{ r.end_date }}</td>
          <td>{{ r.notes or '' }}</td>
          <td><small>{{ r.created_at.strftime('%Y-%m-%d %H:%M') }}</small></td>
        </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}<p>No pending requests.</p>{% endif %}

  <div style="margin-top:1rem;">
    <a class="btn-primary" href="{{ url_for('request_booking') }}">Request another stay</a>
  </div>
</section>
{% endblock %}""",

    "request.html": r"""{% extends "base.html" %}
{% block content %}
<h2>Request time at the Lake House</h2>
<form method="POST" class="card" style="padding:1rem;" data-validate="booking">
  {{ form.hidden_tag() }}
  <div class="grid">
    <label>{{ form.name.label }} {{ form.name(size=32) }}</label>
    <label>{{ form.email.label }} {{ form.email(size=32) }}</label>
    <label>{{ form.phone.label }} {{ form.phone(size=20) }}</label>
    <label>{{ form.member_type.label }} {{ form.member_type() }}</label>
    <!-- Force type='text' + class for Flatpickr -->
    <label>{{ form.start_date.label }} {{ form.start_date(class_="datepicker", type="text", placeholder="YYYY-MM-DD") }}</label>
    <label>{{ form.end_date.label }} {{ form.end_date(class_="datepicker", type="text", placeholder="YYYY-MM-DD") }}</label>
  </div>
  <label>{{ form.notes.label }} {{ form.notes(rows=3) }}</label>
  <label>{{ form.subscribe_sms() }} {{ form.subscribe_sms.label }}</label>
  <button class="btn-primary" type="submit">Submit Request</button>
</form>
{% endblock %}""",

    "admin_login.html": r"""{% extends "base.html" %}
{% block content %}
<h2>Admin Login</h2>
<form method="POST" class="card" style="padding:1rem;">
  {{ form.hidden_tag() }}
  <label>{{ form.email.label }} {{ form.email(size=32) }}</label>
  <label>{{ form.password.label }} {{ form.password(size=32) }}</label>
  <button class="btn-primary" type="submit">Sign in</button>
</form>
{% endblock %}""",

    "admin_requests.html": r"""{% extends "base.html" %}
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
        <form method="POST" action="{{ url_for('approve_request', req_id=r.id) }}" style="display:inline;"><button>Approve</button></form>
        <form method="POST" action="{{ url_for('deny_request', req_id=r.id) }}" style="display:inline;"><button class="secondary">Deny</button></form>
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
        <form method="POST" action="{{ url_for('deny_request', req_id=r.id) }}" style="display:inline;"><button class="secondary">Revoke</button></form>
        <form method="POST" action="{{ url_for('cancel_request', req_id=r.id) }}" style="display:inline;"><button class="contrast">Cancel</button></form>
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
}

def _ensure_templates_present():
    """
    Write templates if missing; optionally force refresh with FORCE_TEMPLATE_REFRESH=1
    or if the version marker is missing.
    """
    try:
        TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
        force = os.getenv("FORCE_TEMPLATE_REFRESH", "0") == "1"
        for name, content in DEFAULT_TEMPLATES.items():
            p = TEMPLATES_DIR / name
            if force or (not p.exists()) or ("LAKEHOUSE_BASE_V3" in content and "LAKEHOUSE_BASE_V3" not in (p.read_text(encoding="utf-8") if p.exists() else "")):
                p.write_text(content, encoding="utf-8")
                app.logger.info(f"[bootstrap] wrote template: {p}")
    except Exception as e:
        app.logger.error(f"[bootstrap] failed creating templates: {e}")

_ensure_templates_present()

# -----------------------------
# Session helpers
# -----------------------------
def login_member(member: Member):
    session["user_member_id"] = member.id

def logout_member():
    session.pop("user_member_id", None)

def current_member():
    mid = session.get("user_member_id")
    if not mid:
        return None
    return Member.query.get(mid)

def is_admin():
    return bool(session.get("is_admin"))

def current_admin_email():
    return os.getenv("ADMIN_EMAIL") if is_admin() else None

# -----------------------------
# Email/SMS helpers (DRY-RUN aware)
# -----------------------------
def send_email(to_email: str, subject: str, body: str) -> bool:
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "0") or 0)
    user = os.getenv("SMTP_USER")
    pwd  = os.getenv("SMTP_PASS")
    from_addr = os.getenv("EMAIL_FROM", user or "no-reply@lakehouse.local")
    secure = (os.getenv("SMTP_SECURE", "starttls") or "starttls").lower()
    timeout = int(os.getenv("SMTP_TIMEOUT", "20"))

    if not host or not port:
        print(f"[EMAIL DRY-RUN] To: {to_email} | Subj: {subject}\n{body}")
        return True

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_email

    try:
        if secure == "ssl" or port == 465:
            with smtplib.SMTP_SSL(host=host, port=port, timeout=timeout) as server:
                if user and pwd:
                    server.login(user, pwd)
                server.send_message(msg)
        else:
            with smtplib.SMTP(host=host, port=port, timeout=timeout) as server:
                server.ehlo()
                if secure == "starttls" or port == 587:
                    server.starttls(); server.ehlo()
                if user and pwd:
                    server.login(user, pwd)
                server.send_message(msg)
        print(f"[EMAIL OK] sent → {to_email}")
        return True
    except (smtplib.SMTPException, socket.error) as e:
        print(f"[EMAIL ERROR] {type(e).__name__}: {e}")
        return False

def send_sms(to_number: str, body: str) -> bool:
    sid   = os.getenv("TWILIO_ACCOUNT_SID")
    token = os.getenv("TWILIO_AUTH_TOKEN")
    from_number = os.getenv("TWILIO_FROM_NUMBER")
    msid  = os.getenv("TWILIO_MESSAGING_SERVICE_SID")

    if not TwilioClient or not sid or not token or (not from_number and not msid):
        print(f"[SMS DRY-RUN] To: {to_number} | {body}")
        return True

    try:
        client = TwilioClient(sid, token)
        kwargs = {"to": to_number, "body": body}
        if msid: kwargs["messaging_service_sid"] = msid
        else:    kwargs["from_"] = from_number
        msg = client.messages.create(**kwargs)
        print(f"[SMS OK] sid={msg.sid} to={to_number}")
        return True
    except Exception as e:
        print(f"[SMS ERROR] {e!r}")
        return False

def _tx(kind, status, booking=None, member=None, target=None, meta=None):
    try:
        rec = DataTransaction(
            kind=kind,
            status=status,
            booking_request_id=(booking.id if booking else None),
            member_id=(member.id if member else None),
            target=target,
            meta_json=json.dumps(meta or {}, ensure_ascii=False),
        )
        db.session.add(rec)
        db.session.commit()
    except Exception as e:
        print(f"[TX-LOG ERROR] {e!r}")

# -----------------------------
# Optional Google Calendar helpers
# -----------------------------
SCOPES = ["https://www.googleapis.com/auth/calendar"]

def _get_google_creds():
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
    try:
        service = build("calendar", "v3", credentials=creds)
        event_body = {
            "summary": summary,
            "description": description,
            "start": {"date": start_date.isoformat()},
            "end": {"date": (end_date + timedelta(days=1)).isoformat()},  # all-day, exclusive end
        }
        event = service.events().insert(calendarId=calendar_id, body=event_body).execute()
        print(f"[Calendar] Inserted event id={event.get('id')}")
        return event.get("id")
    except Exception as e:
        print(f"[Calendar] Insert failed: {e!r}")
        return None

def remove_event_from_calendar(event_id):
    calendar_id = os.getenv("GOOGLE_CALENDAR_ID")
    if not (calendar_id and event_id and GOOGLE_OK):
        return False
    creds = _get_google_creds()
    if not creds:
        return False
    try:
        service = build("calendar", "v3", credentials=creds)
        service.events().delete(calendarId=calendar_id, eventId=event_id).execute()
        print(f"[Calendar] Deleted event id={event_id}")
        return True
    except Exception as e:
        print(f"[Calendar] Failed to delete event: {e}")
        return False

# -----------------------------
# Booking conflict helpers (END-EXCLUSIVE)
# -----------------------------
def ranges_overlap(a_start, a_end, b_start, b_end):
    """
    Treat end days as EXCLUSIVE so back-to-back bookings are allowed:
    [a_start, a_end) overlaps [b_start, b_end)  <=>  not (a_end <= b_start or b_end <= a_start)
    """
    return not (a_end <= b_start or b_end <= a_start)

def find_conflicts(start_date, end_date, exclude_request_id=None):
    q = BookingRequest.query.filter(BookingRequest.status == "approved")
    if exclude_request_id:
        q = q.filter(BookingRequest.id != exclude_request_id)
    return [r for r in q.all() if ranges_overlap(start_date, end_date, r.start_date, r.end_date)]

def _log(action, request_id, details=""):
    db.session.add(AuditLog(action=action, request_id=request_id, admin_email=current_admin_email(), details=details))
    db.session.commit()

def _snapshot_booking(br: BookingRequest):
    try:
        snap = BookingRequestHistory(
            booking_request_id=br.id,
            admin_email=current_admin_email(),
            status=br.status,
            start_date=br.start_date,
            end_date=br.end_date,
            notes=br.notes,
            calendar_event_id=br.calendar_event_id,
        )
        db.session.add(snap)
        db.session.commit()
    except Exception as e:
        print(f"[HISTORY ERROR] {e!r}")

def _notify_status(br: BookingRequest):
    member = br.member
    subj = f"Lake House request {br.status.upper()}: {br.start_date} - {br.end_date}"
    body = f"Hi {member.name},\n\nYour request for {br.start_date} to {br.end_date} has been {br.status}."
    if br.status == "approved":
        body += "\nWe added it to the lake house calendar."
    elif br.status == "denied":
        body += "\nPlease contact the admin with any questions."
    send_email(member.email, subj, body)

# -----------------------------
# Ensure DB + indexes (Render-safe)
# -----------------------------
@app.before_request
def _ensure_db():
    if not getattr(app, "_db_inited", False):
        with app.app_context():
            db.create_all()
            try:
                db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_booking_status ON booking_request(status);"))
                db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_tx_created_at ON data_transaction(created_at);"))
                db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_hist_booking ON booking_request_history(booking_request_id);"))
                db.session.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_member_email ON member(email);"))
                db.session.commit()
            except Exception as e:
                print(f"[INDEX WARN] {e!r}")
        app._db_inited = True

# -----------------------------
# Public auth + aliases (includes signout)
# -----------------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_member():
        return redirect(url_for("dashboard"))
    form = SignupForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        m = Member.query.filter(Member.email == email).first()
        if m and m.password_hash:
            flash("An account with that email already exists. Please sign in.", "warning")
            return redirect(url_for("signin"))
        if not m:
            m = Member(
                name=form.name.data.strip(),
                email=email,
                phone=(form.phone.data.strip() if form.phone.data else None),
                member_type="non_due",
            )
            m.set_password(form.password.data)
            db.session.add(m)
        else:
            m.name = form.name.data.strip()
            m.phone = form.phone.data.strip() if form.phone.data else m.phone
            m.set_password(form.password.data)
        db.session.commit()
        login_member(m)
        flash("Account created. Welcome!", "success")
        return redirect(url_for("dashboard"))
    return render_template("auth_signup.html", form=form)

@app.route("/signin", methods=["GET", "POST"])
def signin():
    if current_member():
        return redirect(url_for("dashboard"))
    form = SigninForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        m = Member.query.filter(Member.email == email).first()
        if not m or not m.password_hash or not m.check_password(form.password.data):
            flash("Invalid email or password.", "danger")
        else:
            login_member(m)
            flash("Signed in.", "success")
            return redirect(url_for("dashboard"))
    return render_template("auth_signin.html", form=form)

@app.route("/signout")
def signout():
    logout_member()
    flash("Signed out.", "info")
    return redirect(url_for("root"))

# Friendly short aliases
@app.route("/login", methods=["GET", "POST"])
def login():
    return signin()

@app.route("/logout")
def logout():
    return signout()

@app.route("/register", methods=["GET", "POST"])
def register():
    return signup()

# -----------------------------
# Root + dashboard
# -----------------------------
@app.route("/", methods=["GET"])
def root():
    if current_member():
        return redirect(url_for("dashboard"))
    return render_template("landing.html")

@app.route("/dashboard", methods=["GET"])
def dashboard():
    m = current_member()
    if not m:
        return redirect(url_for("signin"))
    today = date.today()
    upcoming = (BookingRequest.query
                .filter_by(member_id=m.id, status="approved")
                .filter(BookingRequest.end_date >= today)
                .order_by(BookingRequest.start_date.asc())
                .all())
    pending = (BookingRequest.query
               .filter_by(member_id=m.id, status="pending")
               .order_by(BookingRequest.created_at.desc())
               .all())
    return render_template("dashboard.html", me=m, upcoming=upcoming, pending=pending)

# -----------------------------
# Request form + aliases (client+server blocking, end-day allowed)
# -----------------------------
def _request_form_handler():
    me = current_member()
    form = RequestForm()

    # Prefill when signed in
    if me and request.method == "GET":
        form.name.data = me.name
        form.email.data = me.email
        form.phone.data = me.phone
        form.member_type.data = me.member_type

    if form.validate_on_submit():
        # Server: end must be after start
        if form.end_date.data <= form.start_date.data:
            flash("End date must be after start date.", "danger")
            return render_template("request.html", form=form)

        # Server: END-EXCLUSIVE overlap check
        overlaps = find_conflicts(form.start_date.data, form.end_date.data)
        if overlaps:
            flash("Those dates overlap an existing booking. Note: end days are allowed to touch the next start day.", "danger")
            return render_template("request.html", form=form)

        # find or create member
        member = me or Member.query.filter_by(email=form.email.data.strip().lower()).first()
        if not member:
            member = Member(
                name=form.name.data.strip(),
                email=form.email.data.strip().lower(),
                phone=(form.phone.data.strip() if form.phone.data else None),
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
        _snapshot_booking(br)

        flash("Request submitted! You’ll receive an email confirmation.", "success")
        return redirect(url_for("dashboard") if current_member() else url_for("root"))

    # IMPORTANT: ensure the rendered inputs are text + class=datepicker (see template)
    return render_template("request.html", form=form)

@app.route("/request", methods=["GET", "POST"])
def request_booking():
    return _request_form_handler()

@app.route("/request/new", methods=["GET", "POST"])
def request_new():
    return _request_form_handler()

# Backward-compat aliases (in case templates link differently)
@app.route("/request_booking", methods=["GET", "POST"])
def request_booking_old():
    return _request_form_handler()

@app.route("/request_new", methods=["GET", "POST"])
def request_new_old():
    return _request_form_handler()

# Booked dates API for datepicker (INTERIOR DAYS ONLY: start .. end-1)
@app.get("/api/booked-dates")
def api_booked_dates():
    rows = (BookingRequest.query
            .filter(BookingRequest.status == "approved")
            .with_entities(BookingRequest.start_date, BookingRequest.end_date)
            .all())
    blocked = set()
    for s, e in rows:
        d = s
        while d < e:  # stop BEFORE e so end-day is free for back-to-back bookings
            blocked.add(d.isoformat())
            d += timedelta(days=1)
    return jsonify(sorted(blocked))

# -----------------------------
# Calendar (embed) + ICS
# -----------------------------
@app.route("/calendar")
def calendar_view():
    cal_id = os.getenv("GOOGLE_CALENDAR_EMBED_ID") or os.getenv("GOOGLE_CALENDAR_ID")
    embed_src = None
    if cal_id:
        embed_src = (
            "https://calendar.google.com/calendar/embed"
            f"?src={quote(cal_id)}&ctz=America%2FNew_York&mode=MONTH&showPrint=0&showTitle=0"
        )
    return render_template_string("""{% extends "base.html" %}{% block content %}
    <h2>Lake House Calendar</h2>
    {% if embed_src %}
      <iframe src="{{ embed_src }}" style="border:0; width:100%; height:75vh;" frameborder="0" scrolling="no"></iframe>
      <p style="margin-top:0.75rem;">Need an ICS? <a href="{{ url_for('calendar_ics') }}">Subscribe to the iCal feed</a>.</p>
    {% else %}
      <article class="warning"><strong>Calendar not configured.</strong>
      <p>Set <code>GOOGLE_CALENDAR_EMBED_ID</code> (recommended) or <code>GOOGLE_CALENDAR_ID</code> in Render, then redeploy.</p></article>
    {% endif %}
    {% endblock %}""", embed_src=embed_src)

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
        "BEGIN:VCALENDAR","VERSION:2.0","PRODID:-//LakeHouse//Bookings//EN",
        "CALSCALE:GREGORIAN","METHOD:PUBLISH","X-WR-CALNAME:Lake House Bookings",
    ]
    for r in events:
        uid = f"lakehouse-{r.id}@example.local"
        dtstamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        dtstart = r.start_date.strftime("%Y%m%d")
        dtend = (r.end_date + timedelta(days=1)).strftime("%Y%m%d")  # exclusive end
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
    ics = "\r\n".join(lines + ["END:VCALENDAR"]) + "\r\n"
    return Response(ics, mimetype="text/calendar")

# -----------------------------
# Admin
# -----------------------------
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
    return render_template("admin_login.html", form=form)

@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    flash("Admin logged out.", "info")
    return redirect(url_for("root"))

@app.route("/admin/requests")
def admin_requests():
    if not is_admin():
        return redirect(url_for("admin_login"))

    dues_first = case((Member.member_type == "due", 0), else_=1)

    pending = (db.session.query(BookingRequest).join(Member)
               .filter(BookingRequest.status == "pending")
               .order_by(dues_first.asc(), BookingRequest.created_at.asc())
               .all())
    approved = (db.session.query(BookingRequest).join(Member)
               .filter(BookingRequest.status == "approved")
               .order_by(dues_first.asc(), BookingRequest.start_date.asc())
               .all())
    denied = (db.session.query(BookingRequest).join(Member)
               .filter(BookingRequest.status == "denied")
               .order_by(BookingRequest.created_at.desc())
               .all())

    return render_template(
        "admin_requests.html",
        pending=pending, approved=approved, denied=denied,
        logs=AuditLog.query.order_by(AuditLog.created_at.desc()).limit(50).all(),
    )

@app.post("/admin/requests/<int:req_id>/approve")
def approve_request(req_id):
    if not is_admin():
        return redirect(url_for("admin_login"))
    br = BookingRequest.query.get_or_404(req_id)

    conflicts = find_conflicts(br.start_date, br.end_date, exclude_request_id=br.id)
    if conflicts:
        conflict_list = ", ".join(f"{c.member.name}({c.start_date}→{c.end_date})" for c in conflicts)
        flash(f"Cannot approve: date conflict with {conflict_list}.", "danger")
        return redirect(url_for("admin_requests"))

    br.status = "approved"
    db.session.commit()
    _snapshot_booking(br)
    _notify_status(br)
    _log("approve", br.id, "Approved")
    flash("Request approved.", "success")
    return redirect(url_for("admin_requests"))

@app.post("/admin/requests/<int:req_id>/deny")
def deny_request(req_id):
    if not is_admin():
        return redirect(url_for("admin_login"))
    br = BookingRequest.query.get_or_404(req_id)
    br.status = "denied"
    db.session.commit()
    _snapshot_booking(br)
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
    db.session.commit()
    _snapshot_booking(br)
    _notify_status(br)
    _log("cancel", br.id, "Cancelled by admin")
    flash("Request cancelled.", "warning")
    return redirect(url_for("admin_requests"))

# -----------------------------
# Diagnostics & exports
# -----------------------------
@app.route("/_routes")
def _routes():
    rules = []
    for r in app.url_map.iter_rules():
        methods = ",".join(sorted(m for m in r.methods if m not in ("HEAD","OPTIONS")))
        rules.append({"rule": str(r), "endpoint": r.endpoint, "methods": methods})
    return jsonify(sorted(rules, key=lambda x: x["rule"]))

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

@app.route("/admin/exports/transactions.csv")
def export_transactions_csv():
    if not is_admin():
        return redirect(url_for("admin_login"))
    rows = DataTransaction.query.order_by(DataTransaction.created_at.desc()).all()
    f = StringIO()
    w = csv.writer(f)
    w.writerow(["id","created_at","kind","status","booking_request_id","member_id","target","meta_json"])
    for r in rows:
        w.writerow([r.id, r.created_at.isoformat(), r.kind, r.status,
                    r.booking_request_id, r.member_id, r.target, r.meta_json or "{}"])
    return Response(
        f.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition":"attachment; filename=transactions.csv"}
    )

@app.route("/admin/exports/requests.jsonl")
def export_requests_jsonl():
    if not is_admin():
        return redirect(url_for("admin_login"))
    rows = BookingRequest.query.order_by(BookingRequest.created_at.desc()).all()
    out = []
    for r in rows:
        out.append({
            "id": r.id,
            "member": {"id": r.member.id, "name": r.member.name, "email": r.member.email, "type": r.member.member_type},
            "start_date": r.start_date.isoformat(),
            "end_date": r.end_date.isoformat(),
            "status": r.status,
            "calendar_event_id": r.calendar_event_id,
            "created_at": r.created_at.isoformat(),
            "notes": r.notes,
        })
    return jsonify(out)

# Friendly 404
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

# -----------------------------
# CLI
# -----------------------------
@app.cli.command("init-db")
def init_db():
    db.create_all()
    try:
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_booking_status ON booking_request(status);"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_tx_created_at ON data_transaction(created_at);"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_hist_booking ON booking_request_history(booking_request_id);"))
        db.session.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_member_email ON member(email);"))
        db.session.commit()
    except Exception as e:
        print(f"[INDEX WARN] {e!r}")
    print("Database initialized.")

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000)
