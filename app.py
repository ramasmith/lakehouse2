# app.py — full booking app with calendar/email/SMS + resilient homepage
import os, sys
from pathlib import Path
from datetime import datetime, date, timedelta
from flask import Flask, render_template, render_template_string, request, redirect, url_for, flash, session, Response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, DateField, TextAreaField, SubmitField, BooleanField, PasswordField
from wtforms.validators import DataRequired, Email, Length
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
from jinja2 import TemplateNotFound
from flask import render_template_string, flash

# Notifications
import smtplib
from email.mime.text import MIMEText
from twilio.rest import Client as TwilioClient

# Google Calendar OAuth user credentials (desktop flow)
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

from sqlalchemy import case

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
    """Use token.json if present; else attempt local OAuth (only works if Render secret files aren’t used)."""
    creds = None
    token_path = BASE_DIR / "token.json"
    client_secret_path = BASE_DIR / "client_secret.json"
    # On Render, these are provided as Secret Files mounted at the working dir (same as BASE_DIR)
    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception as e:
                print(f"[Calendar] Refresh failed: {e}")
                creds = None
        if not creds:
            if not client_secret_path.exists():
                print("[Calendar] client_secret.json not found. Skipping calendar integration.")
                return None
            # NOTE: This OAuth flow opens a browser — works locally; on Render you should upload token.json from local.
            flow = InstalledAppFlow.from_client_secrets_file(str(client_secret_path), SCOPES)
            creds = flow.run_local_server(port=0)
            with open(token_path, "w") as token:
                token.write(creds.to_json())
    return creds

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
    conflicts = []
    for r in q.all():
        if ranges_overlap(start_date, end_date, r.start_date, r.end_date):
            conflicts.append(r)
    return conflicts

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
# Routes — resilient homepage
# -----------------------------

@app.before_request
def _ensure_db():
    # Only run once per process
    if not getattr(app, "_db_inited", False):
        with app.app_context():
            db.create_all()
        app._db_inited = True


@app.route("/", methods=["GET", "POST"])
def home():
    # If template exists, render full booking form; else inline fallback so site always loads
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
                f"{member.name} ({member.member_type}) requested {br.start_date} - {br.end_date}.\nNotes: {br.notes or '(none)'}\nReview: {request.url_root}admin/requests"
            )
            send_email(
                member.email,
                "We received your lake house request", "Hi {member.name},\n\nWe received your request for {br.start_date} to {br.end_date}. We'll notify you once it's approved or denied.\n\nThanks!"
            )
            if form.subscribe_sms.data and member.phone:
                send_sms(member.phone, f"Lake House: request received for {br.start_date} - {br.end_date}.")

            _log("create", br.id, f"Created by {member.email}")
            flash("Request submitted! You'll receive an email confirmation.", "success")
            return redirect(url_for("home"))
        return render_template("home.html", form=form)
    # fallback inline
    return render_template_string("""
      <!doctype html><html lang="en"><head><meta charset="utf-8"><title>Lake House</title></head>
      <body>
        <h1>Lake House Bookings</h1>
        <p>✅ App is running, but <code>templates/home.html</code> is missing. Create it and redeploy.</p>
        <p><a href="/_diag">Diagnostics</a></p>
      </body></html>
    """)

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        admin_email = os.getenv("ADMIN_EMAIL", "")
        admin_password = os.getenv("ADMIN_PASSWORD", "")
        if form.email.data.strip().lower() == admin_email.strip().lower() and form.password.data == admin_password:
            session["is_admin"] = True
            flash("Welcome, admin!", "success")
            return redirect(url_for("admin_requests"))
        else:
            flash("Invalid credentials", "danger")
    return render_template("admin_login.html", form=form)

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("home"))

@app.route("/admin/_diag")
def admin_diag():
    # masks the email so it’s not fully exposed
    raw = os.getenv("ADMIN_EMAIL", "")
    masked = (raw[:2] + "***" + raw[-2:]) if len(raw) >= 5 else ("***" if raw else "")
    return {
        "has_secret_key": bool(app.config.get("SECRET_KEY")),
        "has_admin_email": bool(os.getenv("ADMIN_EMAIL")),
        "admin_email_masked": masked,
        "has_admin_password": bool(os.getenv("ADMIN_PASSWORD")),
    }, 200

@app.route("/_ls")
def _ls():
    import os
    tree = []
    for root, dirs, files in os.walk(".", topdown=True):
        # keep output small
        if "/.venv" in root or "/site-packages" in root:
            continue
        tree.append({"root": root, "dirs": sorted(dirs), "files": sorted(files)})
    return {"cwd": os.getcwd(), "tree": tree}, 200
    
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
            ok_pwd   = form.password.data == admin_password
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
    


# Public read-only ICS feed for approved bookings
@app.route("/calendar.ics")
def calendar_ics():
    events = BookingRequest.query.filter(BookingRequest.status=="approved").order_by(BookingRequest.start_date.asc()).all()
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
    ics = "\\r\\n".join(lines + ["END:VCALENDAR"]) + "\\r\\n"
    return Response(ics, mimetype="text/calendar")

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

# Reminders (daily at 09:00)
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
