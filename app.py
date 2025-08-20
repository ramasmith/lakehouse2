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
  {% end
