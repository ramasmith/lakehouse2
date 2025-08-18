# Minimal resilient app.py that works even if templates are missing.
import os, sys
from pathlib import Path
from flask import Flask, render_template, render_template_string, jsonify

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"

# Force Flask to look in <repo root>/templates
app = Flask(__name__, template_folder=str(TEMPLATES_DIR))
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret")

@app.route("/")
def index():
    # Try home.html, then index.html, else inline HTML fallback so the site loads.
    if (TEMPLATES_DIR / "home.html").exists():
        return render_template("home.html")
    if (TEMPLATES_DIR / "index.html").exists():
        return render_template("index.html")
    return render_template_string("""
      <!doctype html><html lang="en"><head><meta charset="utf-8"><title>Lake House</title></head>
      <body>
        <h1>Lake House Bookings</h1>
        <p>✅ App is running on Render.</p>
        <p>But I can't find <code>templates/home.html</code>. Create it at the repo root under <code>templates/</code>.</p>
        <p><strong>Next:</strong> Create <code>templates/home.html</code> (all lowercase) then redeploy.</p>
        <p><a href="/_diag">Diagnostics</a></p>
      </body></html>
    """)

# Simple diagnostics so we can verify files Render sees
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

