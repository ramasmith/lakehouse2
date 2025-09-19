# app.py — Lake House bookings
# End-exclusive model: allow back-to-back bookings (end == next start).
# Changes vs. prior:
# - SQL overlap checks (no Python filtering surprises)
# - Detailed debug logging shows the exact conflicting rows
# - Diagnostic route /_test_overlap?s=YYYY-MM-DD&e=YYYY-MM-DD
# - Google Calendar + ICS use DB end (already exclusive)
# - Flatpickr: only start dates are disabled from approved interiors

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
from sqlalchemy import case, text, and_
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
    end_date = db.Column(db.Date, nullable=False)  # END-EXCLUSIVE in all logic
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
    # We render these as text (Flatpickr) but WTForms still parses them as dates
    start_date = DateField("Start Date", validators=[DataRequired()], format="%Y-%m-%d")
    end_date = DateField("End Date", validators=[DataRequired()], format="%Y-%m-%d")
    notes = TextAreaField("Notes (optional)")
    subscribe_sms = BooleanField("Send me SMS updates")
    submit = SubmitField("Submit Request")


c
