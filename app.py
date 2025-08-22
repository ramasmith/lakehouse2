# app.py — Lake House bookings (Modern summer-lake styling + disabled dates + popup + server validation)
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
from wtforms import StringField, SelectField, TextAreaField, SubmitField, BooleanField, PasswordField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import case, text

# Optional: Google Calendar
try:
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build
    from google.auth.transport.requests import Request
    GOOGLE_OK = True
except Exception:
    GOOGLE_OK = False

# Optional: SMTP / SMS (email DRY-RUN by default)
import smtplib
from email.mime.text import MIMEText
try:
    from twilio.rest import Client as TwilioClient
except Exception:
    TwilioClient = None

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"

app = Flask(__name__, template_folder=str(TEMPLATES_DIR))
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-secret")
# For Render persistent disk, prefer: sqlite:////var/data/lakehouse.db
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI", "sqlite:///lakehouse.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# --------------------------------
# Models
# --------------------------------
class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    phone = db.Column(db.String(32))
    member_type = db.Column(db.String(32), nullable=False, default="non_due")  # "due" or "non_due"
    password_hash = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    def set_password(self, pwd: str):
        self.password_hash = generate_password_hash(pwd)

    def check_password(self, pwd: str) -> bool:
        return bool(self.password_hash) and check_password_hash(self.password_hash, pwd)

class BookingRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('member.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(16), nullable=False, default="pending")  # pending/approved/denied/cancelled
    calendar_event_id = db.Column(db.String(128))
    member = db.relationship("Member", backref=db.backref("requests", lazy=True))

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(32), nullable=False)  # approve/deny/cancel/create
    request_id = db.Column(db.Integer, db.ForeignKey('booking_request.id'))
    admin_email = db.Column(db.String(255))
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
# --- Admin login (adds the missing 'admin_login' endpoint) ---
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    form = AdminLoginForm()
    if request.method == "POST":
        if not form.validate_on_submit():
            flash("Please check your email and password.", "danger")
        else:
            admin_email = (os.getenv("ADMIN_EMAIL") or "").strip().lower()
            admin_password = os.getenv("ADMIN_PASSWORD") or ""
            ok_email = form.email.data.strip().lower() == admin_email
            ok_pwd = form.password.data == admin_password
            if ok_email and ok_pwd:
                session["is_admin"] = True
                flash("Welcome, admin!", "success")
                return redirect(url_for("admin_requests"))
            else:
                flash("Invalid admin credentials.", "danger")
    return render_template("admin_login.html", form=form)

# --------------------------------
# Forms
# --------------------------------
class SigninForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign in")

class SignupForm(FlaskForm):
    name = StringField("Full name", validators=[DataRequired(), Length(max=120)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    phone = StringField("Phone (optional)")
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6, max=128)])
    submit = SubmitField("Create account")

class RequestForm(FlaskForm):
    name = StringField("Your Name", validators=[DataRequired(), Length(max=120)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    phone = StringField("Phone (optional)")
    member_type = SelectField("Membership Type",
        choices=[("due","Due-paying member"), ("non_due","Non due-paying member")],
        validators=[DataRequired()])
    # Use text inputs so Flatpickr truly takes over
    start_date = StringField("Start Date", validators=[DataRequired()], render_kw={"autocomplete":"off"})
    end_date   = StringField("End Date",   validators=[DataRequired()], render_kw={"autocomplete":"off"})
    notes = TextAreaField("Notes (optional)")
    subscribe_sms = BooleanField("Send me SMS updates")
    submit = SubmitField("Submit Request")

# --------------------------------
# Self-healing templates with modern/summer-lake styling
# --------------------------------
DEFAULT_TEMPLATES = {
"base.html": """<!doctype html>
<html lang="en" data-theme="light"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Lake House Bookings</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&family=Catamaran:wght@700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
  <style>
    :root {
      --lake-900:#0f4c5c; --lake-700:#2c7da0; --lake-500:#48a6c6; --lake-300:#90d4f7;
      --sun-400:#ffd166; --sun-500:#fcbf49;
      --leaf-500:#2a9d8f; --dune-50:#f6f4ee; --dune-100:#f0ece4;
      --ink:#0b1320; --muted:#6b7280; --card: #ffffffcc;
      --ring: rgba(15, 76, 92, .15);
      --danger:#ef4444; --warning:#f59e0b; --success:#10b981;
      --shadow: 0 10px 24px rgba(15,76,92,.12), 0 2px 8px rgba(15,76,92,.08);
      --radius: 16px;
    }
    html, body { height:100%; background:
      radial-gradient(1200px 800px at 80% -10%, var(--sun-400) 0%, transparent 60%),
      radial-gradient(1200px 800px at -10% 120%, var(--lake-300) 0%, transparent 55%),
      linear-gradient(180deg, #eef6fb 0%, var(--dune-50) 100%);
      font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      color: var(--ink);
    }
    header.hero {
      margin: 0 0 1.5rem 0; border-radius: var(--radius);
      padding: 1.25rem 1.25rem; background:
      linear-gradient(135deg, rgba(72,166,198,.25), rgba(250, 240, 219,.45));
      box-shadow: var(--shadow); display:flex; align-items:center; gap:1rem;
    }
    header.hero .title {
      font-family: Catamaran, Inter, sans-serif; letter-spacing:.3px; margin:0;
      font-weight:700; font-size: clamp(1.3rem, 2.2vw + .5rem, 2rem);
      color: var(--lake-900);
    }
    nav.glass {
      backdrop-filter: blur(6px);
      background: rgba(255,255,255,.65);
      border: 1px solid rgba(15,76,92,.08);
      padding:.6rem .9rem; border-radius: 999px; box-shadow: var(--shadow);
      display:flex; align-items:center; justify-content:space-between; gap: .75rem; margin: 1rem 0 1.25rem 0;
    }
    nav.glass a { color: var(--lake-900); font-weight:600; border-radius: 999px; padding:.45rem .8rem; }
    nav.glass a:hover { background: rgba(72,166,198,.12); }
    .wrap { max-width: 1100px; margin-inline: auto; padding: 0 1rem 2rem; }

    .card {
      background: var(--card); border: 1px solid rgba(15,76,92,.06);
      border-radius: var(--radius); box-shadow: var(--shadow);
      padding: 1.1rem 1.1rem;
    }
    .grid.tight { --pico-grid-gap: .85rem; }

    .btn, button, input[type=submit]{
      border-radius: 999px; border:1px solid rgba(15,76,92,.12);
      box-shadow: 0 1px 0 rgba(255,255,255,.5) inset, 0 1px 2px rgba(0,0,0,.04);
      background: linear-gradient(180deg, #fff, #f6fbff);
      padding: .55rem 1rem; font-weight:600;
    }
    .btn-primary{
      background: linear-gradient(180deg, var(--lake-500), var(--lake-700));
      color:#fff; border-color: transparent;
    }
    .btn-primary:hover{ filter: saturate(1.05) brightness(1.02); }

    /* Table polish */
    table[role=grid] { background:#fff; border-radius: var(--radius); overflow:hidden; box-shadow: var(--shadow); }
    thead th { background: linear-gradient(180deg, #f8fbfd, #eef6fb); color: var(--lake-900); }
    tbody tr:hover { background: #f9fcff; }

    /* Badges & tags */
    .badge { padding:.24rem .5rem; border-radius: 999px; font-size:.75rem; font-weight:700; }
    .badge.due { background: var(--leaf-500); color:white; }
    .badge.non_due { background: var(--lake-700); color:white; }
    .tag { font-size: .75rem; padding:.22rem .5rem; border-radius:999px; background:#eef2f7; color:#334155; }

    /* Toast-style flash messages */
    .toasts { position: fixed; top: 14px; right: 14px; display:flex; gap:.5rem; flex-direction:column; z-index: 9999; }
    .toast { padding:.7rem 1rem; border-radius: 10px; box-shadow: var(--shadow); border:1px solid rgba(15,76,92,.08); background:#fff; }
    .toast.success { border-left: 6px solid var(--success); }
    .toast.info    { border-left: 6px solid var(--lake-500); }
    .toast.warning { border-left: 6px solid var(--warning); }
    .toast.danger  { border-left: 6px solid var(--danger); }

    /* Flatpickr disabled dates look clearly off-limits */
    .flatpickr-day.disabled, .flatpickr-day.disabled:hover {
      background: repeating-linear-gradient(45deg, #eaeff5, #eaeff5 6px, #dfe7ee 6px, #dfe7ee 12px);
      color:#b0b9c4; cursor:not-allowed; text-decoration: line-through;
    }
    .flatpickr-day.selected { background: var(--lake-700); border-color: var(--lake-700); }
    .flatpickr-day.today { border-color: var(--lake-500); }

    /* Forms */
    label > input, label > textarea, label > select {
      border-radius: 12px !important; border:1px solid rgba(15,76,92,.18);
      box-shadow: none;
    }
    label > input:focus, label > textarea:focus, label > select:focus {
      outline: 2px solid var(--ring);
      border-color: var(--lake-500);
    }
    footer { color:#6b7280; }

    /* Tiny helper */
    .muted{ color:#6b7280; }
  </style>
</head>
<body>
  <div class="wrap">
    <nav class="glass">
      <div style="display:flex; align-items:center; gap:.6rem;">
        <span style="width:36px;height:36px;border-radius:10px;background:linear-gradient(180deg,var(--lake-500),var(--lake-700));display:inline-block;box-shadow:var(--shadow)"></span>
        <strong style="font-family:Catamaran,Inter,sans-serif;color:var(--lake-900);font-size:1.1rem;">Lake House</strong>
      </div>
      <div style="display:flex; gap:.35rem; align-items:center;">
        {% if session.get('user_member_id') %}
          <a href="{{ url_for('dashboard') }}">Dashboard</a>
          <a href="{{ url_for('request_booking') }}">New request</a>
          <a href="{{ url_for('signout') }}">Sign out</a>
        {% else %}
          <a href="{{ url_for('root') }}">Home</a>
          <a href="{{ url_for('signin') }}">Sign in</a>
          <a href="{{ url_for('signup') }}">Create account</a>
        {% endif %}
        <a href="{{ url_for('calendar_view') }}">Calendar</a>
        <a href="{{ url_for('calendar_ics') }}">ICS</a>
      </div>
    </nav>

    <header class="hero">
      <h1 class="title">{% block title %}Bookings{% endblock %}</h1>
      <span class="muted">Easy summer stays by the lake</span>
    </header>

    <div class="toasts">
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          {% for category, message in messages %}
            <div class="toast {{ category }}">{{ message }}</div>
          {% endfor %}
        {% endif %}
      {% endwith %}
    </div>

    {% block content %}{% endblock %}
    <footer style="margin-top:2rem">Made for summer • Book with ease • <span class="muted">Lake breeze included</span></footer>
  </div>
  <script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
</body></html>""",

"landing.html": """{% extends "base.html" %}
{% block title %}Welcome{% endblock %}
{% block content %}
  <section class="card">
    <hgroup>
      <h2 style="margin:0">Welcome to the Lake House</h2>
      <p class="muted" style="margin:.25rem 0 0">Sign in to view your bookings and request new dates.</p>
    </hgroup>
    <div class="grid tight" style="margin-top:1rem;">
      <a class="btn btn-primary" href="{{ url_for('signin') }}">Sign in</a>
      <a class="btn" href="{{ url_for('signup') }}">Create account</a>
    </div>
  </section>
{% endblock %}""",

"dashboard.html": """{% extends "base.html" %}
{% block title %}Your bookings{% endblock %}
{% block content %}
  <section class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:.75rem;">
      <h2 style="margin:0">Your bookings</h2>
      <a class="btn btn-primary" href="{{ url_for('request_booking') }}">Request new booking</a>
    </div>

    {% if upcoming or pending %}
      {% if upcoming %}
        <h3 style="margin-top:1rem">Approved</h3>
        <table role="grid">
          <thead><tr><th>Dates</th><th>Notes</th><th>Created</th></tr></thead>
          <tbody>
            {% for r in upcoming %}
              <tr>
                <td>{{ r.start_date }} → {{ r.end_date }}</td>
                <td>{{ r.notes or "-" }}</td>
                <td><small>{{ r.created_at.strftime("%Y-%m-%d %H:%M") }}</small></td>
              </tr>
            {% endfor %}
          </tbody>
        </table>
      {% endif %}
      {% if pending %}
        <h3 style="margin-top:1rem">Pending</h3>
        <table role="grid">
          <thead><tr><th>Dates</th><th>Notes</th><th>Created</th></tr></thead>
          <tbody>
            {% for r in pending %}
              <tr>
                <td>{{ r.start_date }} → {{ r.end_date }}</td>
                <td>{{ r.notes or "-" }}</td>
                <td><small>{{ r.created_at.strftime("%Y-%m-%d %H:%M") }}</small></td>
              </tr>
            {% endfor %}
          </tbody>
        </table>
      {% endif %}
    {% else %}
      <p class="muted">You have no bookings yet.</p>
    {% endif %}
  </section>
{% endblock %}""",

"request.html": """{% extends "base.html" %}
{% block title %}Request a booking{% endblock %}
{% block content %}
  <section class="card">
    <h2 style="margin:0 0 .5rem 0">Request a booking</h2>
    <form method="POST">
      {{ form.hidden_tag() }}
      <div class="grid tight">
        <label>{{ form.name.label }} {{ form.name(size=32, readonly=me is not none) }}</label>
        <label>{{ form.email.label }} {{ form.email(size=32, readonly=me is not none) }}</label>
        <label>{{ form.phone.label }} {{ form.phone(size=20) }}</label>
        <label>{{ form.member_type.label }} {{ form.member_type(disabled=me is not none) }}</label>
        <label>Start {{ form.start_date(id="start_date", class_="date-input", placeholder="YYYY-MM-DD") }}</label>
        <label>End {{ form.end_date(id="end_date", class_="date-input", placeholder="YYYY-MM-DD") }}</label>
      </div>
      <label style="margin-top:.5rem">{{ form.notes.label }} {{ form.notes(rows=3) }}</label>
      <label style="margin-top:.25rem">{{ form.subscribe_sms() }} {{ form.subscribe_sms.label }}</label>
      <div style="margin-top:.75rem; display:flex; gap:.5rem;">
        <button type="submit" class="btn btn-primary">Submit Request</button>
        <a class="btn" href="{{ url_for('dashboard') }}">Cancel</a>
      </div>
    </form>
  </section>

  <script>
    async function initPickers() {
      try {
        const resp = await fetch("{{ url_for('api_booked_dates') }}");
        const data = await resp.json();
        const disabledRanges = (data && data.disabled) ? data.disabled : [];

        function iso(d) { return d.toISOString().slice(0,10); }
        function isISOBlocked(s) {
          for (const r of disabledRanges) {
            if (s >= r.from && s <= r.to) return true;
          }
          return false;
        }
        function isBlockedDate(d) { return isISOBlocked(iso(d)); }

        const common = {
          dateFormat: "Y-m-d",
          disableMobile: true,
          allowInput: false,
          disable: disabledRanges,
          onChange: function(selectedDates, dateStr, instance) {
            if (selectedDates.length && isBlockedDate(selectedDates[0])) {
              alert("Those dates conflict with an existing booking. Please choose different dates.");
              instance.clear();
            }
          }
        };

        const startPicker = flatpickr("#start_date", {
          ...common,
          onChange: function(selectedDates, dateStr, instance) {
            common.onChange(selectedDates, dateStr, instance);
            if (selectedDates.length) {
              endPicker.set("minDate", selectedDates[0]);
            } else {
              endPicker.set("minDate", null);
            }
          }
        });

        const endPicker = flatpickr("#end_date", { ...common });
      } catch (e) {
        console.error("Failed to load disabled dates", e);
      }
    }
    initPickers();
  </script>
{% endblock %}""",

"auth_signin.html": """{% extends "base.html" %}
{% block title %}Sign in{% endblock %}
{% block content %}
  <section class="card">
    <h2 style="margin:0 0 .5rem 0">Sign in</h2>
    <form method="POST">
      {{ form.hidden_tag() }}
      <label>{{ form.email.label }} {{ form.email(size=32) }}</label>
      <label>{{ form.password.label }} {{ form.password(size=32) }}</label>
      <div style="margin-top:.5rem; display:flex; gap:.5rem;">
        <button type="submit" class="btn btn-primary">Sign in</button>
        <a class="btn" href="{{ url_for('signup') }}">Create account</a>
      </div>
    </form>
  </section>
{% endblock %}""",

"auth_signup.html": """{% extends "base.html" %}
{% block title %}Create account{% endblock %}
{% block content %}
  <section class="card">
    <h2 style="margin:0 0 .5rem 0">Create account</h2>
    <form method="POST">
      {{ form.hidden_tag() }}
      <label>{{ form.name.label }} {{ form.name(size=32) }}</label>
      <label>{{ form.email.label }} {{ form.email(size=32) }}</label>
      <label>{{ form.phone.label }} {{ form.phone(size=20) }}</label>
      <label>{{ form.password.label }} {{ form.password(size=32) }}</label>
      <div style="margin-top:.5rem; display:flex; gap:.5rem;">
        <button type="submit" class="btn btn-primary">Create account</button>
        <a class="btn" href="{{ url_for('signin') }}">Sign in</a>
      </div>
    </form>
  </section>
{% endblock %}""",

"calendar_embed.html": """{% extends "base.html" %}
{% block title %}Calendar{% endblock %}
{% block content %}
  <section class="card">
    <h2 style="margin:0 0 .5rem 0">Lake House Calendar</h2>
    {% if embed_src %}
      <iframe src="{{ embed_src }}" style="border:0; width:100%; height:75vh; border-radius:12px" frameborder="0" scrolling="no"></iframe>
      <p class="muted" style="margin-top:0.75rem;">Need an ICS? <a href="{{ url_for('calendar_ics') }}">Subscribe to the iCal feed</a>.</p>
    {% else %}
      <article class="warning">
        <strong>Calendar not configured.</strong>
        <p>Set <code>GOOGLE_CALENDAR_EMBED_ID</code> (recommended) or <code>GOOGLE_CALENDAR_ID</code> and redeploy.</p>
      </article>
    {% endif %}
  </section>
{% endblock %}""",
}

def _ensure_templates_present():
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    for name, content in DEFAULT_TEMPLATES.items():
        p = TEMPLATES_DIR / name
        # Always (re)write if file missing; if present, keep user's edits
        if not p.exists():
            p.write_text(content, encoding="utf-8")
            app.logger.info(f"[bootstrap] wrote missing template: {p}")

_ensure_templates_present()

# --------------------------------
# Helpers: auth, email/sms, calendar, auditing
# --------------------------------
def login_member(m: Member):
    session["user_member_id"] = m.id

def logout_member():
    session.pop("user_member_id", None)

def current_member():
    mid = session.get("user_member_id")
    return Member.query.get(mid) if mid else None

def _log(action, request_id, details=""):
    db.session.add(AuditLog(action=action, request_id=request_id, admin_email=os.getenv("ADMIN_EMAIL"), details=details))
    db.session.commit()

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
    msg["Subject"] = subject; msg["From"] = from_addr; msg["To"] = to_email
    try:
        if secure == "ssl" or port == 465:
            with smtplib.SMTP_SSL(host=host, port=port, timeout=timeout) as s:
                if user and pwd: s.login(user, pwd)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host=host, port=port, timeout=timeout) as s:
                s.ehlo()
                if secure == "starttls" or port == 587:
                    s.starttls(); s.ehlo()
                if user and pwd: s.login(user, pwd)
                s.send_message(msg)
        return True
    except (smtplib.SMTPException, socket.error) as e:
        print(f"[EMAIL ERROR] {e}")
        return False

SCOPES = ["https://www.googleapis.com/auth/calendar"]

def _get_google_creds():
    if not GOOGLE_OK:
        return None
    token_path = BASE_DIR / "token.json"
    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)
        if not creds.valid and creds.refresh_token:
            try:
                creds.refresh(Request())
                token_path.write_text(creds.to_json(), encoding="utf-8")
            except Exception as e:
                print(f"[Calendar] refresh failed: {e}")
                return None
        return creds
    return None

def _gcal_list_events_between(start_date: date, end_date: date):
    cal_id = os.getenv("GOOGLE_CALENDAR_ID")
    if not (cal_id and GOOGLE_OK):
        return []
    creds = _get_google_creds()
    if not creds:
        return []
    time_min = datetime.combine(start_date, datetime.min.time()).isoformat() + "Z"
    time_max = datetime.combine(end_date + timedelta(days=1), datetime.min.time()).isoformat() + "Z"
    try:
        service = build("calendar", "v3", credentials=creds)
        items = service.events().list(
            calendarId=cal_id, timeMin=time_min, timeMax=time_max,
            singleEvents=True, orderBy="startTime"
        ).execute().get("items", [])
        return items
    except Exception as e:
        print(f"[Calendar] list failed: {e}")
        return []

def _parse_gcal_date_or_datetime(when: dict):
    if "date" in when and when["date"]:
        return datetime.fromisoformat(when["date"]).date()
    dt_raw = when.get("dateTime")
    if not dt_raw:
        return date.today()
    if dt_raw.endswith("Z"):
        dt_raw = dt_raw[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(dt_raw).date()
    except Exception:
        try:
            base = dt_raw.split("+")[0]
            return datetime.fromisoformat(base).date()
        except Exception:
            return date.today()

def find_calendar_conflicts(s: date, e: date):
    items = _gcal_list_events_between(s, e)
    conflicts = []
    req_start, req_end_excl = s, e + timedelta(days=1)
    for ev in items:
        s_raw, e_raw = ev.get("start", {}), ev.get("end", {})
        g_start = _parse_gcal_date_or_datetime(s_raw)
        if "date" in e_raw and e_raw.get("date"):
            g_end_excl = datetime.fromisoformat(e_raw["date"]).date()
        else:
            g_end_excl = _parse_gcal_date_or_datetime(e_raw) + timedelta(days=1)
        if not (req_end_excl <= g_start or g_end_excl <= req_start):
            title = ev.get("summary") or "(untitled)"
            conflicts.append(f"{title} [{g_start} → {(g_end_excl - timedelta(days=1))}]")
    return conflicts

def ranges_overlap(a_start, a_end, b_start, b_end):
    return not (a_end < b_start or b_end < a_start)

def find_conflicts(s: date, e: date, exclude_id: int | None = None):
    q = BookingRequest.query.filter(BookingRequest.status == "approved")
    if exclude_id:
        q = q.filter(BookingRequest.id != exclude_id)
    return [r for r in q.all() if ranges_overlap(s, e, r.start_date, r.end_date)]

# --------------------------------
# DB bootstrap + indexes
# --------------------------------
@app.before_request
def _ensure_db():
    if not getattr(app, "_db_inited", False):
        with app.app_context():
            db.create_all()
            try:
                db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_booking_status ON booking_request(status);"))
                db.session.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_member_email ON member(email);"))
                db.session.commit()
            except Exception as e:
                print(f"[INDEX WARN] {e!r}")
        app._db_inited = True

# --------------------------------
# Public pages / auth
# --------------------------------
@app.route("/")
def root():
    if current_member():
        return redirect(url_for("dashboard"))
    return render_template("landing.html")

@app.route("/signin", methods=["GET","POST"])
def signin():
    if current_member():
        return redirect(url_for("dashboard"))
    form = SigninForm()
    if form.validate_on_submit():
        m = Member.query.filter(Member.email.ilike(form.email.data.strip())).first()
        if not m or not m.check_password(form.password.data):
            flash("Invalid email or password.", "danger")
        else:
            login_member(m)
            return redirect(url_for("dashboard"))
    return render_template("auth_signin.html", form=form)

@app.route("/signup", methods=["GET","POST"])
def signup():
    if current_member():
        return redirect(url_for("dashboard"))
    form = SignupForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        existing = Member.query.filter(Member.email.ilike(email)).first()
        if existing:
            flash("An account with that email already exists. Please sign in.", "warning")
            return redirect(url_for("signin"))
        m = Member(name=form.name.data.strip(), email=email, phone=(form.phone.data or "").strip(), member_type="non_due")
        m.set_password(form.password.data)
        db.session.add(m); db.session.commit()
        login_member(m)
        return redirect(url_for("dashboard"))
    return render_template("auth_signup.html", form=form)

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
    upcoming = (BookingRequest.query
                .filter_by(member_id=m.id, status="approved")
                .order_by(BookingRequest.start_date.asc())
                .all())
    pending = (BookingRequest.query
               .filter_by(member_id=m.id, status="pending")
               .order_by(BookingRequest.created_at.desc())
               .all())
    return render_template("dashboard.html", upcoming=upcoming, pending=pending)
    
@app.route("/admin/requests")
def admin_requests():
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))
    # ... your existing admin listing logic ...

@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    flash("Admin logged out.", "info")
    return redirect(url_for("root"))

# --- Public auth aliases expected by templates ---
@app.route("/login", methods=["GET", "POST"])
def login():  # alias so url_for('login') works
    return signin()

@app.route("/logout")
def logout():  # alias so url_for('logout') works
    return signout()

@app.route("/register", methods=["GET", "POST"])
def register():  # alias so url_for('register') works if used anywhere
    return signup()

# --------------------------------
# Request a booking
# --------------------------------
@app.route("/request", methods=["GET","POST"])
def request_booking():
    m = current_member()
    form = RequestForm()

    # Prefill identity fields for signed-in members
    if request.method == "GET" and m:
        form.name.data = m.name
        form.email.data = m.email
        form.phone.data = m.phone
        form.member_type.data = m.member_type

    if form.validate_on_submit():
        # Parse dates (Flatpickr emits YYYY-MM-DD)
        try:
            s = datetime.strptime(form.start_date.data.strip(), "%Y-%m-%d").date()
            e = datetime.strptime(form.end_date.data.strip(), "%Y-%m-%d").date()
        except Exception:
            flash("Please select valid dates.", "danger")
            return render_template("request.html", form=form, me=m)

        # end > start rule
        if e <= s:
            flash("End date must be after start date.", "danger")
            return render_template("request.html", form=form, me=m)

        # DB conflicts (reject)
        if find_conflicts(s, e):
            flash("Those dates overlap with an approved booking. Please choose different dates.", "danger")
            return render_template("request.html", form=form, me=m)

        # Optional: GCal warning (non-blocking)
        gc_list = find_calendar_conflicts(s, e)
        if gc_list:
            flash("Warning: Google Calendar shows overlapping events: " + "; ".join(gc_list), "warning")

        # Upsert member (if not signed in)
        if not m:
            email = form.email.data.strip().lower()
            m = Member.query.filter(Member.email.ilike(email)).first()
            if not m:
                m = Member(
                    name=form.name.data.strip(),
                    email=email,
                    phone=(form.phone.data or "").strip(),
                    member_type=form.member_type.data
                )
                db.session.add(m); db.session.flush()  # get ID

        br = BookingRequest(
            member_id=m.id,
            start_date=s,
            end_date=e,
            notes=form.notes.data
        )
        db.session.add(br); db.session.commit()
        _log("create", br.id, f"Created by {m.email}")
        flash("Request submitted! We’ll email you after review.", "success")
        return redirect(url_for("dashboard") if current_member() else url_for("root"))

    return render_template("request.html", form=form, me=m)
    
# Back-compat alias so old templates don't crash
@app.route("/request/new")
def request_new():
    return redirect(url_for("request_booking"), code=302)
    
# API for disabled date ranges (used by Flatpickr)
@app.get("/api/booked-dates")
def api_booked_dates():
    # Pull approved bookings
    rows = (BookingRequest.query
            .filter(BookingRequest.status == "approved")
            .order_by(BookingRequest.start_date.asc())
            .all())
    ranges = []
    for r in rows:
        ranges.append({"from": r.start_date.isoformat(), "to": r.end_date.isoformat()})

    # Optionally merge GCal all-day/timed events as blocked (non-authoritative)
    try:
        if GOOGLE_OK and os.getenv("GOOGLE_CALENDAR_ID"):
            # Use a wide window to gather conflicts (next ~18 months)
            today = date.today()
            horizon = today + timedelta(days=548)
            items = _gcal_list_events_between(today, horizon)
            for ev in items:
                s_raw, e_raw = ev.get("start", {}), ev.get("end", {})
                g_start = _parse_gcal_date_or_datetime(s_raw)
                if "date" in e_raw and e_raw.get("date"):
                    g_end_excl = datetime.fromisoformat(e_raw["date"]).date()
                else:
                    g_end_excl = _parse_gcal_date_or_datetime(e_raw) + timedelta(days=1)
                ranges.append({"from": g_start.isoformat(), "to": (g_end_excl - timedelta(days=1)).isoformat()})
    except Exception as e:
        print(f"[api_booked_dates] gcal merge failed: {e}")

    # Merge overlapping ranges
    if not ranges:
        return jsonify({"disabled": []})
    merged = []
    for r in sorted(ranges, key=lambda x: x["from"]):
        if not merged or r["from"] > merged[-1]["to"]:
            merged.append({"from": r["from"], "to": r["to"]})
        else:
            merged[-1]["to"] = max(merged[-1]["to"], r["to"])
    return jsonify({"disabled": merged})

# --------------------------------
# Calendar views
# --------------------------------
@app.route("/calendar")
def calendar_view():
    cal_id = os.getenv("GOOGLE_CALENDAR_EMBED_ID") or os.getenv("GOOGLE_CALENDAR_ID")
    embed_src = None
    if cal_id:
        embed_src = ("https://calendar.google.com/calendar/embed"
                     f"?src={quote(cal_id)}&ctz=America%2FNew_York&mode=MONTH&showPrint=0&showTitle=0")
    return render_template("calendar_embed.html", embed_src=embed_src, calendar_id=cal_id)

@app.route("/calendar.ics")
def calendar_ics():
    events = (BookingRequest.query
              .filter(BookingRequest.status == "approved")
              .order_by(BookingRequest.start_date.asc()).all())
    def esc(s): return (s or "").replace("\\","\\\\").replace(";","\\;").replace(",","\\,")
    def fold(line, limit=75):
        if len(line)<=limit: return [line]
        out=[]; 
        while len(line)>limit: out.append(line[:limit]); line=" "+line[limit:]
        out.append(line); return out
    lines = ["BEGIN:VCALENDAR","VERSION:2.0","PRODID:-//LakeHouse//Bookings//EN","CALSCALE:GREGORIAN","METHOD:PUBLISH","X-WR-CALNAME:Lake House Bookings"]
    for r in events:
        uid=f"lakehouse-{r.id}@example.local"
        dtstamp=datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        dtstart=r.start_date.strftime("%Y%m%d")
        dtend=(r.end_date+timedelta(days=1)).strftime("%Y%m%d")
        summary=esc(f"Lake House: {r.member.name} ({r.member.member_type})")
        desc=esc((r.notes or "")+f"\\nMember email: {r.member.email}")
        ev=["BEGIN:VEVENT",f"UID:{uid}",f"DTSTAMP:{dtstamp}",f"DTSTART;VALUE=DATE:{dtstart}",f"DTEND;VALUE=DATE:{dtend}",f"SUMMARY:{summary}",f"DESCRIPTION:{desc}","END:VEVENT"]
        for line in ev: lines.extend(fold(line))
    ics="\r\n".join(lines+["END:VCALENDAR"])+"\r\n"
    return Response(ics, mimetype="text/calendar")

# --------------------------------
# Diagnostics
# --------------------------------
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

# Friendly 404
@app.errorhandler(404)
def not_found(e):
    html = """
    <!doctype html><html><head>
      <meta charset='utf-8'><title>Not Found</title>
      <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
    </head><body><main class="container">
      <h2>Not Found</h2>
      <ul>
        <li><a href="/">Home</a></li>
        <li><a href="/dashboard">Dashboard</a></li>
        <li><a href="/request">Request</a></li>
        <li><a href="/calendar">Calendar</a></li>
        <li><a href="/_routes">Route list</a></li>
      </ul>
    </main></body></html>
    """
    return make_response(html, 404)

# --------------------------------
# CLI
# --------------------------------
@app.cli.command("init-db")
def init_db():
    db.create_all()
    try:
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_booking_status ON booking_request(status);"))
        db.session.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_member_email ON member(email);"))
        db.session.commit()
    except Exception as e:
        print(f"[INDEX WARN] {e!r}")
    print("Database initialized.")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT","5000")))
