# app.py — Lake House bookings (Render-safe, single-file, self-healing templates + accounts/history/exports + disabled/greyed-out unavailable dates + end>start validation)
import os, sys, socket, json, csv
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
from wtforms.validators import DataRequired, Email, Length, ValidationError
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
# For Render persistent disk (recommended):
#   SQLALCHEMY_DATABASE_URI=sqlite:////var/data/lakehouse.db
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI", "sqlite:///lakehouse.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# =========================
# Models
# =========================
class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(32), nullable=True)
    member_type = db.Column(db.String(32), nullable=False, default="non_due")  # "due"|"non_due"
    password_hash = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # convenience helpers
    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return bool(self.password_hash) and check_password_hash(self.password_hash, password)


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


class DataTransaction(db.Model):
    __tablename__ = "data_transaction"
    id = db.Column(db.Integer, primary_key=True)
    kind = db.Column(db.String(40), nullable=False)   # "email","sms","gcal.insert","gcal.delete"
    status = db.Column(db.String(20), nullable=False) # "success","error","skip"
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

# =========================
# Forms
# =========================
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

    # Server-side rule: end > start
    def validate_end_date(self, field):
        if self.start_date.data and field.data and field.data <= self.start_date.data:
            raise ValidationError("End date must be later than start date.")

class AdminLoginForm(FlaskForm):
    email = StringField("Admin Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign in")

class SignupForm(FlaskForm):
    name = StringField("Full name", validators=[DataRequired(), Length(max=120)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    phone = StringField("Phone (optional)")
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Create account")

class SigninForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign in")

# =========================
# Self-healing templates
# =========================
DEFAULT_TEMPLATES = {
"base.html": """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lake House Bookings</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
<style>
  .badge { padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.75rem; }
  .badge.due { background:#0ea5e9; color:#fff; }
  .badge.non_due { background:#94a3b8; color:#fff; }
  .tag { font-size:0.75rem; padding:0.15rem 0.35rem; border-radius:999px; background:#e2e8f0; color:#334155; }
  code { font-size:0.8rem; }
</style>
</head>
<body>
  <main class="container">
    <nav>
      <ul><li><strong>Lake House Bookings</strong></li></ul>
      <ul>
        {% if session.get('user_member_id') %}
          <li><a href="{{ url_for('dashboard') }}">Dashboard</a></li>
          <li><a href="{{ url_for('request_new') }}">New request</a></li>
          <li><a href="{{ url_for('signout') }}">Sign out</a></li>
        {% else %}
          <li><a href="{{ url_for('signin') }}">Sign in</a></li>
          <li><a href="{{ url_for('signup') }}">Create account</a></li>
        {% endif %}
        <li><a href="{{ url_for('calendar_view') }}">Calendar</a></li>
        <li><a href="{{ url_for('calendar_ics') }}">ICS feed</a></li>
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
        <div>
          {% for category, message in messages %}
            <article class="{{ category }}">{{ message }}</article>
          {% endfor %}
        </div>
      {% endif %}
    {% endwith %}

    {% block content %}{% endblock %}

    <footer style="margin-top:3rem; font-size:0.9rem; color:#64748b;">
      Built with Flask • Conflict detection • Dues priority • Audit log • ICS feed • Accounts • Disabled dates
    </footer>
  </main>
</body></html>
""",

"landing.html": """{% extends "base.html" %}
{% block content %}
  <section>
    <h2>Welcome to the Lake House</h2>
    <p>Please <a href="{{ url_for('signin') }}">sign in</a> or <a href="{{ url_for('signup') }}">create an account</a> to view your bookings or request a new stay.</p>
  </section>
{% endblock %}
""",

"dashboard.html": """{% extends "base.html" %}
{% block content %}
<h2>My dashboard</h2>
<p><strong>{{ me.name }}</strong> &lt;{{ me.email }}&gt;</p>

<h3>Upcoming</h3>
{% if upcoming %}
  <ul>
    {% for r in upcoming %}
      <li>{{ r.start_date }} → {{ r.end_date }} <span class="badge due">{{ r.status }}</span></li>
    {% endfor %}
  </ul>
{% else %}
  <p>No upcoming stays.</p>
{% endif %}

<h3>Pending</h3>
{% if pending %}
  <ul>
    {% for r in pending %}
      <li>{{ r.start_date }} → {{ r.end_date }} <span class="tag">{{ r.status }}</span></li>
    {% endfor %}
  </ul>
{% else %}
  <p>No pending requests. <a href="{{ url_for('request_new') }}">Request a new booking</a>.</p>
{% endif %}
{% endblock %}
""",

# Booking form with Flatpickr disabling unavailable dates and client-side start<end guard
"request_form.html": """{% extends "base.html" %}
{% block content %}
<h2>Request time at the Lake House</h2>
<form method="POST" id="requestForm">
  {{ form.hidden_tag() }}
  <div class="grid">
    <label>{{ form.name.label }} {{ form.name(size=32) }}</label>
    <label>{{ form.email.label }} {{ form.email(size=32) }}</label>
    <label>{{ form.phone.label }} {{ form.phone(size=20) }}</label>
    <label>{{ form.member_type.label }} {{ form.member_type() }}</label>
    <label>{{ form.start_date.label }} {{ form.start_date(id="start_date") }}</label>
    <label>{{ form.end_date.label }} {{ form.end_date(id="end_date") }}</label>
  </div>
  <label>{{ form.notes.label }} {{ form.notes(rows=3) }}</label>
  <label>{{ form.subscribe_sms() }} {{ form.subscribe_sms.label }}</label>
  <button type="submit" id="submitBtn">Submit Request</button>

  {% if form.errors %}
    <article class="warning" style="margin-top:1rem;">
      <strong>Fix the following:</strong>
      <ul>
      {% for field, errs in form.errors.items() %}
        {% for e in errs %}<li>{{ field }}: {{ e }}</li>{% endfor %}
      {% endfor %}
      </ul>
    </article>
  {% endif %}
</form>

<hr>
<p><small><strong>Unavailable dates</strong> are greyed out and cannot be selected.</small></p>

<!-- Flatpickr -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
<script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
<script>
  (function(){
    const unavailable = {{ unavailable_dates|tojson }};
    const today = new Date().toISOString().slice(0,10);

    function disableDates(date) {
      const d = date.toISOString().slice(0,10);
      return unavailable.includes(d);
    }

    const sharedOptions = {
      dateFormat: "Y-m-d",
      minDate: today,
      disable: disableDates,
      allowInput: false,
    };

    const fpStart = flatpickr("#start_date", Object.assign({}, sharedOptions, {
      onChange: function(selectedDates, dateStr, instance){
        const endInput = document.getElementById("end_date");
        if (dateStr && endInput.value && endInput.value <= dateStr) {
          endInput.value = "";
        }
        if (dateStr) {
          endPicker.set('minDate', dateStr);  // end must be after start
        }
        validatePair();
      }
    }));

    const endPicker = flatpickr("#end_date", Object.assign({}, sharedOptions, {
      onChange: function(selectedDates, dateStr, instance){
        validatePair();
      }
    }));

    function validatePair(){
      const s = document.getElementById("start_date").value;
      const e = document.getElementById("end_date").value;
      const btn = document.getElementById("submitBtn");
      btn.disabled = false;
      if (s && e && s >= e){
        btn.disabled = true;
        alert("End date must be later than start date.");
      }
    }

    // Double safety: prevent submit if end<=start
    document.getElementById("requestForm").addEventListener("submit", function(ev){
      const s = document.getElementById("start_date").value;
      const e = document.getElementById("end_date").value;
      if (s && e && s >= e){
        ev.preventDefault();
        alert("End date must be later than start date.");
        return false;
      }
      // Prevent submitting if any disabled date lies within the range
      if (s && e){
        const sd = new Date(s);
        const ed = new Date(e);
        for (let d = new Date(sd); d < ed; d.setDate(d.getDate()+1)){
          const iso = d.toISOString().slice(0,10);
          if (unavailable.includes(iso)){
            ev.preventDefault();
            alert("Your selected range includes unavailable dates.");
            return false;
          }
        }
      }
    });
  })();
</script>
{% endblock %}
""",

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
{% endblock %}
""",

"admin_requests.html": """{% extends "base.html" %}
{% block content %}
<h2>Pending Requests</h2>
{% if pending %}
<table role="grid">
  <thead><tr><th>Member</th><th>Dates</th><th>Notes</th><th>Conflicts</th><th>Actions</th></tr></thead>
  <tbody>
  {% for r in pending %}
    <tr>
      <td>{{ r.member.name }} ({{ r.member.member_type }})<br><small>{{ r.member.email }}</small></td>
      <td>{{ r.start_date }} → {{ r.end_date }}</td>
      <td>{{ r.notes }}</td>
      <td>
        {% set g = gcal_conf.get(r.id) %}
        {% if g and g|length %}
          <span class="badge non_due">GCal conflict</span>
          <details style="margin-top:0.25rem;">
            <summary>details</summary>
            <ul style="margin:0.25rem 0 0 1rem;">
              {% for item in g %}
                <li>{{ item }}</li>
              {% endfor %}
            </ul>
          </details>
        {% else %}
          <span class="tag">none</span>
        {% endif %}
      </td>
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
{% endblock %}
""",

"calendar_embed.html": """{% extends "base.html" %}
{% block content %}
<h2>Lake House Calendar</h2>
{% if embed_src %}
  <iframe src="{{ embed_src }}" style="border:0; width:100%; height:75vh;" frameborder="0" scrolling="no"></iframe>
  <p style="margin-top:0.75rem;">
    Need an ICS? <a href="{{ url_for('calendar_ics') }}">Subscribe to the iCal feed</a>.
  </p>
{% else %}
  <article class="warning"><strong>Calendar not configured.</strong>
    <p>Set <code>GOOGLE_CALENDAR_EMBED_ID</code> (recommended) or <code>GOOGLE_CALENDAR_ID</code> in Render, then redeploy.</p>
  </article>
{% endif %}
{% endblock %}
""",

"auth_signup.html": """{% extends "base.html" %}
{% block content %}
<h2>Create account</h2>
<form method="POST">
  {{ form.hidden_tag() }}
  <label>{{ form.name.label }} {{ form.name(size=32) }}</label>
  <label>{{ form.email.label }} {{ form.email(size=32) }}</label>
  <label>{{ form.phone.label }} {{ form.phone(size=20) }}</label>
  <label>{{ form.password.label }} {{ form.password(size=32) }}</label>
  <button type="submit">Create account</button>
</form>
<p>Already have an account? <a href="{{ url_for('signin') }}">Sign in</a></p>
{% endblock %}
""",

"auth_signin.html": """{% extends "base.html" %}
{% block content %}
<h2>Sign in</h2>
<form method="POST">
  {{ form.hidden_tag() }}
  <label>{{ form.email.label }} {{ form.email(size=32) }}</label>
  <label>{{ form.password.label }} {{ form.password(size=32) }}</label>
  <button type="submit">Sign in</button>
</form>
<p>No account? <a href="{{ url_for('signup') }}">Create one</a></p>
{% endblock %}
""",
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

# =========================
# Auth helpers
# =========================
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

# =========================
# Email/SMS/Calendar helpers
# =========================
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
        else: kwargs["from_"] = from_number
        msg = client.messages.create(**kwargs)
        print(f"[SMS OK] sid={msg.sid} to={to_number}")
        return True
    except Exception as e:
        print(f"[SMS ERROR] {e!r}")
        return False

def _tx(kind, status, booking=None, member=None, target=None, meta=None):
    try:
        rec = DataTransaction(
            kind=kind, status=status,
            booking_request_id=(booking.id if booking else None),
            member_id=(member.id if member else None),
            target=target, meta_json=json.dumps(meta or {}, ensure_ascii=False),
        )
        db.session.add(rec); db.session.commit()
    except Exception as e:
        print(f"[TX-LOG ERROR] {e!r}")

SCOPES = ["https://www.googleapis.com/auth/calendar"]

def _get_google_creds():
    if not GOOGLE_OK:
        print("[Calendar] google libraries not installed; skipping.")
        return None
    token_path = BASE_DIR / "token.json"
    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)
        if not creds.valid and creds.refresh_token:
            try:
                creds.refresh(Request())
                with open(token_path, "w") as f: f.write(creds.to_json())
            except Exception as e:
                print(f"[Calendar] Refresh failed: {e}"); return None
        return creds
    print("[Calendar] token.json not found; skipping calendar sync on server.")
    return None

def add_event_to_calendar(summary, start_date, end_date, description=""):
    calendar_id = os.getenv("GOOGLE_CALENDAR_ID")
    if not (calendar_id and GOOGLE_OK):
        print("[Calendar] Missing GOOGLE_CALENDAR_ID or google libs; skipping.")
        return None
    creds = _get_google_creds()
    if not creds: return None
    try:
        service = build("calendar", "v3", credentials=creds)
        event_body = {
            "summary": summary,
            "description": description,
            "start": {"date": start_date.isoformat()},
            "end": {"date": (end_date + timedelta(days=1)).isoformat()},
        }
        event = service.events().insert(calendarId=calendar_id, body=event_body).execute()
        print(f"[Calendar] Inserted event id={event.get('id')}")
        return event.get("id")
    except Exception as e:
        print(f"[Calendar] Insert failed: {e!r}")
        return None

def remove_event_from_calendar(event_id):
    calendar_id = os.getenv("GOOGLE_CALENDAR_ID")
    if not (calendar_id and event_id and GOOGLE_OK): return False
    creds = _get_google_creds()
    if not creds: return False
    try:
        service = build("calendar", "v3", credentials=creds)
        service.events().delete(calendarId=calendar_id, eventId=event_id).execute()
        print(f"[Calendar] Deleted event id={event_id}")
        return True
    except Exception as e:
        print(f"[Calendar] Failed to delete event: {e}")
        return False

def _parse_gcal_date_or_datetime(when: dict):
    if "date" in when and when["date"]:
        d = datetime.fromisoformat(when["date"]); return d.date()
    dt_raw = when.get("dateTime")
    if not dt_raw: return date.today()
    if dt_raw.endswith("Z"): dt_raw = dt_raw[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(dt_raw).date()
    except Exception:
        try:
            main = dt_raw.split("+")[0].split("-")[0]
            return datetime.fromisoformat(main).date()
        except Exception:
            return date.today()

def _gcal_list_events_between(start_date: date, end_date: date):
    calendar_id = os.getenv("GOOGLE_CALENDAR_ID")
    if not (calendar_id and GOOGLE_OK):
        return []
    creds = _get_google_creds()
    if not creds: return []
    time_min = datetime.combine(start_date, datetime.min.time()).isoformat() + "Z"
    time_max = datetime.combine(end_date + timedelta(days=1), datetime.min.time()).isoformat() + "Z"
    try:
        service = build("calendar", "v3", credentials=creds)
        events = service.events().list(
            calendarId=calendar_id,
            timeMin=time_min, timeMax=time_max,
            singleEvents=True, orderBy="startTime",
        ).execute().get("items", [])
        return events
    except Exception as e:
        print(f"[Calendar] Conflict list failed: {e!r}")
        return []

def find_calendar_conflicts(start_date: date, end_date: date):
    items = _gcal_list_events_between(start_date, end_date)
    conflicts = []
    req_start = start_date
    req_end_exclusive = end_date + timedelta(days=1)
    for ev in items:
        s_raw = ev.get("start", {}); e_raw = ev.get("end", {})
        g_start = _parse_gcal_date_or_datetime(s_raw)
        if "date" in e_raw and e_raw.get("date"):
            g_end_exclusive = datetime.fromisoformat(e_raw["date"]).date()
        else:
            g_end_exclusive = _parse_gcal_date_or_datetime(e_raw) + timedelta(days=1)
        overlaps = not (req_end_exclusive <= g_start or g_end_exclusive <= req_start)
        if overlaps:
            title = ev.get("summary") or "(untitled)"
            disp_start = g_start.isoformat()
            disp_end = (g_end_exclusive - timedelta(days=1)).isoformat()
            conflicts.append(f"{title} [{disp_start} → {disp_end}]")
    return conflicts

# =========================
# Business rules & utilities
# =========================
def ranges_overlap(a_start, a_end, b_start, b_end):
    return not (a_end < b_start or b_end < a_start)

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
        db.session.add(snap); db.session.commit()
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
    ok_email = send_email(member.email, subj, body)
    _tx("email", "success" if ok_email else "error", booking=br, member=member, target=member.email, meta={"subject": subj})
    if member.phone:
        ok_sms = send_sms(member.phone, f"Lake House: your request {br.status} for {br.start_date} - {br.end_date}.")
        _tx("sms", "success" if ok_sms else "error", booking=br, member=member, target=member.phone, meta={"preview": f"{br.status} {br.start_date}→{br.end_date}"})

# =========================
# Ensure DB + indexes (Render-safe)
# =========================
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

# =========================
# Routes — Landing & Auth & Dashboard
# =========================
@app.route("/")
def root():
    if current_member():
        return redirect(url_for("dashboard"))
    return render_template("landing.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_member():
        return redirect(url_for("dashboard"))
    form = SignupForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        existing = Member.query.filter(Member.email.ilike(email)).first()
        if existing and existing.password_hash:
            flash("An account with that email already exists. Please sign in.", "warning")
            return redirect(url_for("signin"))
        if existing and not existing.password_hash:
            m = existing
            m.name = form.name.data.strip()
            m.phone = form.phone.data.strip() if form.phone.data else m.phone
            m.password_hash = generate_password_hash(form.password.data)
        else:
            m = Member(
                name=form.name.data.strip(),
                email=email,
                phone=form.phone.data.strip() if form.phone.data else None,
                member_type="non_due",
                password_hash=generate_password_hash(form.password.data),
            )
            db.session.add(m)
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
        m = Member.query.filter(Member.email.ilike(email)).first()
        if not m or not m.password_hash or not check_password_hash(m.password_hash, form.password.data):
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

@app.route("/dashboard")
def dashboard():
    m = current_member()
    if not m:
        return redirect(url_for("root"))
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

# =========================
# Routes — Create request (with disabled unavailable dates)
# =========================
def _expand_inclusive_dates(start_d: date, end_d: date):
    # yields all calendar dates in [start_d, end_d]
    cur = start_d
    while cur <= end_d:
        yield cur
        cur += timedelta(days=1)

def _collect_unavailable_dates():
    # 1) From approved bookings in DB
    blocked = set()
    approved = BookingRequest.query.filter(BookingRequest.status == "approved").all()
    for r in approved:
        for d in _expand_inclusive_dates(r.start_date, r.end_date):
            blocked.add(d)

    # 2) From Google Calendar (optional)
    cal_id = os.getenv("GOOGLE_CALENDAR_ID")
    if GOOGLE_OK and cal_id:
        # pull a horizon (± 1 year) to keep API light
        start_h = date.today() - timedelta(days=365)
        end_h = date.today() + timedelta(days=365)
        events = _gcal_list_events_between(start_h, end_h)
        for ev in events:
            s_raw = ev.get("start", {}); e_raw = ev.get("end", {})
            s = _parse_gcal_date_or_datetime(s_raw)
            if "date" in e_raw and e_raw.get("date"):
                e_excl = datetime.fromisoformat(e_raw["date"]).date()
                e = e_excl - timedelta(days=1)
            else:
                e = _parse_gcal_date_or_datetime(e_raw)
            for d in _expand_inclusive_dates(s, e):
                blocked.add(d)

    # return ISO strings
    return sorted(d.isoformat() for d in blocked if d >= date.today())

@app.route("/request", methods=["GET", "POST"])
def request_new():
    m = current_member()
    if not m:
        flash("Please sign in to request a booking.", "warning")
        return redirect(url_for("signin"))

    form = RequestForm()

    # Prefill member data
    if request.method == "GET":
        form.name.data = m.name
        form.email.data = m.email
        form.phone.data = m.phone
        form.member_type.data = m.member_type

    # Unavailable date list for JS
    unavailable_dates = _collect_unavailable_dates()

    if form.validate_on_submit():
        # server-side guard: ensure no unavailable date is inside requested range
        sd = form.start_date.data
        ed = form.end_date.data
        picked = set()
        for d in _expand_inclusive_dates(sd, ed - timedelta(days=1)):
            picked.add(d.isoformat())
        bad = picked.intersection(unavailable_dates)
        if bad:
            flash("Your selected range includes unavailable dates. Please choose different dates.", "danger")
            return render_template("request_form.html", form=form, unavailable_dates=unavailable_dates)

        # Also warn (non-blocking) if overlaps approved DB (the above already checks)
        conflicts = find_conflicts(sd, ed)
        if conflicts:
            flash("Heads up: those dates overlap with an approved booking. Admin will review.", "warning")

        # Warn on GCal conflicts (non-blocking)
        gc_conflicts = find_calendar_conflicts(sd, ed)
        if gc_conflicts:
            flash("Google Calendar shows overlapping events: " + "; ".join(gc_conflicts), "warning")

        # upsert member fields
        m.name = form.name.data.strip()
        m.phone = form.phone.data.strip() if form.phone.data else m.phone
        m.member_type = form.member_type.data

        br = BookingRequest(
            member_id=m.id,
            start_date=sd,
            end_date=ed,
            notes=form.notes.data
        )
        db.session.add(br); db.session.commit()
        _snapshot_booking(br)

        # notify admin + requester
        admin_to = os.getenv("ADMIN_EMAIL", m.email)
        ok_admin_email = send_email(
            admin_to,
            "New Lake House Booking Request",
            f"{m.name} ({m.member_type}) requested {br.start_date} - {br.end_date}.\n"
            f"Notes: {br.notes or '(none)'}\nReview: {request.url_root}admin/requests"
        )
        _tx("email", "success" if ok_admin_email else "error", booking=br, member=m, target=admin_to, meta={"subject": "New Lake House Booking Request"})

        ok_user_email = send_email(
            m.email,
            "We received your lake house request",
            f"Hi {m.name},\n\nWe received your request for {br.start_date} to {br.end_date}. "
            "We'll notify you once it's approved or denied.\n\nThanks!"
        )
        _tx("email", "success" if ok_user_email else "error", booking=br, member=m, target=m.email, meta={"subject": "We received your lake house request"})

        if form.subscribe_sms.data and m.phone:
            ok_user_sms = send_sms(m.phone, f"Lake House: request received for {br.start_date} - {br.end_date}.")
            _tx("sms", "success" if ok_user_sms else "error", booking=br, member=m, target=m.phone, meta={"preview": f"request received {br.start_date}→{br.end_date}"})

        _log("create", br.id, f"Created by {m.email}")
        flash("Request submitted! You'll receive an email confirmation.", "success")
        return redirect(url_for("dashboard"))

    return render_template("request_form.html", form=form, unavailable_dates=unavailable_dates)

# =========================
# Calendar & Admin
# =========================
@app.route("/calendar")
def calendar_view():
    cal_id = os.getenv("GOOGLE_CALENDAR_EMBED_ID") or os.getenv("GOOGLE_CALENDAR_ID")
    embed_src = None
    if cal_id:
        embed_src = ("https://calendar.google.com/calendar/embed"
                     f"?src={quote(cal_id)}&ctz=America%2FNew_York&mode=MONTH&showPrint=0&showTitle=0")
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
        return render_template_string("<p>Admin login template missing.</p>"), 200

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("root"))

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

    gcal_conf = {}
    try:
        if GOOGLE_OK and os.getenv("GOOGLE_CALENDAR_ID"):
            for r in pending:
                try:
                    gcal_conf[r.id] = find_calendar_conflicts(r.start_date, r.end_date)
                except Exception as e:
                    app.logger.warning(f"[gcal_conf] failed for req {r.id}: {e}")
        else:
            app.logger.info("[gcal_conf] skipped (no google libs or GOOGLE_CALENDAR_ID)")
    except Exception as e:
        app.logger.warning(f"[gcal_conf] top-level failure: {e}")

    return render_template(
        "admin_requests.html",
        pending=pending, approved=approved, denied=denied,
        logs=AuditLog.query.order_by(AuditLog.created_at.desc()).limit(50).all(),
        gcal_conf=gcal_conf,
    )

@app.post("/admin/requests/<int:req_id>/approve")
def approve_request(req_id):
    if not is_admin(): return redirect(url_for("admin_login"))
    br = BookingRequest.query.get_or_404(req_id)
    conflicts = find_conflicts(br.start_date, br.end_date, exclude_request_id=br.id)
    if conflicts:
        conflict_list = ", ".join(f"{c.member.name}({c.start_date}→{c.end_date})" for c in conflicts)
        flash(f"Cannot approve: date conflict with {conflict_list}.", "danger")
        return redirect(url_for("admin_requests"))
    gc_conflicts = find_calendar_conflicts(br.start_date, br.end_date)
    if gc_conflicts:
        flash("Cannot approve: Google Calendar already has overlapping event(s): " + "; ".join(gc_conflicts), "danger")
        return redirect(url_for("admin_requests"))
    br.status = "approved"
    summary = f"Lake House: {br.member.name} ({br.member.member_type})"
    description = (br.notes or "") + f"\nMember email: {br.member.email}"
    event_id = add_event_to_calendar(summary, br.start_date, br.end_date, description)
    if event_id: br.calendar_event_id = event_id
    db.session.commit()
    _snapshot_booking(br); _notify_status(br); _log("approve", br.id, "Approved and synced to calendar")
    flash("Request approved and calendar updated.", "success")
    return redirect(url_for("admin_requests"))

@app.post("/admin/requests/<int:req_id>/deny")
def deny_request(req_id):
    if not is_admin(): return redirect(url_for("admin_login"))
    br = BookingRequest.query.get_or_404(req_id)
    br.status = "denied"
    ok_del = False
    if br.calendar_event_id:
        ok_del = remove_event_from_calendar(br.calendar_event_id)
        _tx("gcal.delete", "success" if ok_del else "error",
            booking=br, member=br.member, target=os.getenv("GOOGLE_CALENDAR_ID"),
            meta={"event_id": br.calendar_event_id})
        br.calendar_event_id = None
    db.session.commit()
    _snapshot_booking(br); _notify_status(br); _log("deny", br.id, "Denied by admin")
    flash("Request denied." + (" Calendar event removed." if ok_del else ""), "info")
    return redirect(url_for("admin_requests"))

@app.post("/admin/requests/<int:req_id>/cancel")
def cancel_request(req_id):
    if not is_admin(): return redirect(url_for("admin_login"))
    br = BookingRequest.query.get_or_404(req_id)
    br.status = "cancelled"
    ok_del = False
    if br.calendar_event_id:
        ok_del = remove_event_from_calendar(br.calendar_event_id)
        _tx("gcal.delete", "success" if ok_del else "error",
            booking=br, member=br.member, target=os.getenv("GOOGLE_CALENDAR_ID"),
            meta={"event_id": br.calendar_event_id})
        br.calendar_event_id = None
    db.session.commit()
    _snapshot_booking(br); _notify_status(br); _log("cancel", br.id, "Cancelled by admin")
    flash("Request cancelled." + (" Calendar event removed." if ok_del else ""), "warning")
    return redirect(url_for("admin_requests"))

# =========================
# ICS feed
# =========================
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
        dtend = (r.end_date + timedelta(days=1)).strftime("%Y%m%d")
        summary = esc(f"Lake House: {r.member.name} ({r.member.member_type})")
        desc = esc((r.notes or "") + f"\\nMember email: {r.member.email}")
        ev = [
            "BEGIN:VEVENT",
            f"UID:{uid}", f"DTSTAMP:{dtstamp}",
            f"DTSTART;VALUE=DATE:{dtstart}",
            f"DTEND;VALUE=DATE:{dtend}",
            f"SUMMARY:{summary}", f"DESCRIPTION:{desc}",
            "END:VEVENT",
        ]
        for line in ev: lines.extend(fold(line))
    ics = "\r\n".join(lines + ["END:VCALENDAR"]) + "\r\n"
    return Response(ics, mimetype="text/calendar")

# =========================
# Diagnostics & utilities
# =========================
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

@app.route("/_routes")
def _routes():
    rules = []
    for r in app.url_map.iter_rules():
        methods = ",".join(sorted(m for m in r.methods if m not in ("HEAD","OPTIONS")))
        rules.append({"rule": str(r), "endpoint": r.endpoint, "methods": methods})
    return jsonify(sorted(rules, key=lambda x: x["rule"]))

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

# Email/SMS test endpoints (admin only)
@app.route("/admin/_emailtest")
def _emailtest():
    if not is_admin(): return redirect(url_for("admin_login"))
    to = request.args.get("to") or os.getenv("ADMIN_EMAIL")
    if not to:
        return jsonify({"ok": False, "error": "Provide ?to=someone@example.com or set ADMIN_EMAIL"}), 400
    ok = send_email(to, "Lakehouse test email", "This is a test email from the Lakehouse app.")
    _tx("email", "success" if ok else "error", target=to, meta={"subject": "Lakehouse test email"})
    return jsonify({"ok": ok})

@app.route("/admin/_smstest")
def _smstest():
    if not is_admin(): return redirect(url_for("admin_login"))
    to = request.args.get("to")
    if not to:
        return jsonify({"ok": False, "error": "Provide ?to=+1XXXXXXXXXX"}), 400
    ok = send_sms(to, "Lakehouse test SMS: hello from the app.")
    _tx("sms", "success" if ok else "error", target=to, meta={"preview": "Lakehouse test SMS"})
    return jsonify({"ok": ok})

# Exports
@app.route("/admin/exports/transactions.csv")
def export_transactions_csv():
    if not is_admin(): return redirect(url_for("admin_login"))
    rows = DataTransaction.query.order_by(DataTransaction.created_at.desc()).all()
    f = StringIO(); w = csv.writer(f)
    w.writerow(["id","created_at","kind","status","booking_request_id","member_id","target","meta_json"])
    for r in rows:
        w.writerow([r.id, r.created_at.isoformat(), r.kind, r.status,
                    r.booking_request_id, r.member_id, r.target, r.meta_json or "{}"])
    return Response(f.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition":"attachment; filename=transactions.csv"})

@app.route("/admin/exports/requests.jsonl")
def export_requests_jsonl():
    if not is_admin(): return redirect(url_for("admin_login"))
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

@app.route("/admin/exports/history.csv")
def export_history_csv():
    if not is_admin(): return redirect(url_for("admin_login"))
    rows = BookingRequestHistory.query.order_by(BookingRequestHistory.at.desc()).all()
    f = StringIO(); w = csv.writer(f)
    w.writerow(["id","at","booking_request_id","admin_email","status","start_date","end_date","calendar_event_id"])
    for r in rows:
        w.writerow([r.id, r.at.isoformat(), r.booking_request_id, r.admin_email or "",
                    r.status, r.start_date.isoformat(), r.end_date.isoformat(),
                    r.calendar_event_id or ""])
    return Response(f.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition":"attachment; filename=booking_history.csv"})

# 404
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
        <li><a href="/dashboard">Dashboard</a></li>
        <li><a href="/request">New request</a></li>
        <li><a href="/calendar">Calendar</a></li>
        <li><a href="/admin/login">Admin login</a></li>
        <li><a href="/_diag">Diagnostics</a></li>
        <li><a href="/_routes">Route list</a></li>
      </ul>
    </main></body></html>
    """
    return make_response(html, 404)

# =========================
# Reminders (optional scheduler)
# =========================
def send_upcoming_reminders():
    today = date.today()
    in_two_days = today + timedelta(days=2)
    upcoming = BookingRequest.query.filter(
        BookingRequest.status == "approved",
        BookingRequest.start_date == in_two_days
    ).all()
    for br in upcoming:
        ok_email = send_email(
            br.member.email,
            "Lake House reminder",
            f"Hi {br.member.name}, your lake house stay starts on {br.start_date}. Enjoy!"
        )
        _tx("email", "success" if ok_email else "error", booking=br, member=br.member, target=br.member.email, meta={"subject": "Lake House reminder"})
        if br.member.phone:
            ok_sms = send_sms(br.member.phone, f"Reminder: your lake house stay starts on {br.start_date}.")
            _tx("sms", "success" if ok_sms else "error", booking=br, member=br.member, target=br.member.phone, meta={"preview": "stay starts soon"})

if os.getenv("ENABLE_SCHEDULER", "0") == "1":
    from apscheduler.schedulers.background import BackgroundScheduler
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(send_upcoming_reminders, "cron", hour=9, minute=0)
    scheduler.start()

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

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000)
