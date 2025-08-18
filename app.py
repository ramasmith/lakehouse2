from flask import Flask, render_template, request, redirect, url_for, session
import os

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret")

@app.route("/")
def index():
    return render_template("home.html")

@app.route("/admin")
def admin():
    if "admin" not in session:
        return redirect(url_for("login"))
    return render_template("admin.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        if email == os.getenv("ADMIN_EMAIL") and password == os.getenv("ADMIN_PASSWORD"):
            session["admin"] = True
            return redirect(url_for("admin"))
    return render_template("login.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
