from flask import Flask, render_template, request, redirect, url_for, session, abort
from datetime import datetime
import json
from pathlib import Path
from functools import wraps

from encryption import hash_password, verify_password
from validation import validate_login_form, validate_register_form

app = Flask(__name__)
app.secret_key = "dev-secret-change-me"

BASE_DIR = Path(__file__).resolve().parent
USERS_PATH = BASE_DIR / "data" / "users.json"
SCANS_PATH = BASE_DIR / "data" / "scans.json"

# ------------------------
# HELPERS
# ------------------------
def load_json(path):
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("[]", encoding="utf-8")
    return json.loads(path.read_text(encoding="utf-8"))

def save_json(path, data):
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")

def normalize_email(email: str) -> str:
    return (email or "").strip().lower()

def get_current_user():
    email = session.get("user_email")
    if not email:
        return None
    users = load_json(USERS_PATH)
    return next((u for u in users if normalize_email(u["email"]) == email), None)

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not get_current_user():
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


# ------------------------
# HOME
# ------------------------
@app.route("/")
def home():
    return redirect(url_for("login"))


# ------------------------
# LOGIN
# ------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        registered = request.args.get("registered")
        msg = "Account created successfully. Please sign in." if registered else None
        return render_template("auth/login.html", info_message=msg)

    email = request.form.get("email", "")
    password = request.form.get("password", "")

    clean, errors = validate_login_form(email, password)

    if errors:
        return render_template(
            "auth/login.html",
            error="Invalid credentials",
            form={"email": email}
        )

    email_norm = normalize_email(clean["email"])
    users = load_json(USERS_PATH)

    user = next((u for u in users if normalize_email(u["email"]) == email_norm), None)

    try:
        valid = user and verify_password(password, user["password"])
    except Exception:
        valid = False

    if not valid:
        return render_template(
            "auth/login.html",
            error="Invalid credentials",
            form={"email": email}
        )

    session["user_email"] = email_norm
    return redirect(url_for("dashboard"))


# ------------------------
# REGISTER
# ------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("auth/register.html", field_errors={}, form={})

    full_name = request.form.get("full_name", "")
    email = request.form.get("email", "")
    phone = request.form.get("phone", "")  # ✅ ahora sí usamos phone
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")

    clean, errors = validate_register_form(full_name, email, phone, password, confirm)

    if errors:
        return render_template(
            "auth/register.html",
            field_errors=errors,
            form=request.form
        )

    users = load_json(USERS_PATH)
    email_norm = normalize_email(clean["email"])

    if any(normalize_email(u["email"]) == email_norm for u in users):
        return render_template(
            "auth/register.html",
            field_errors={"email": "Email already registered"},
            form=request.form
        )

    new_user = {
        "id": max([u.get("id", 0) for u in users], default=0) + 1,
        "full_name": clean["full_name"],
        "email": email_norm,
        "phone": clean["phone"],  # ✅ guardamos phone
        "password": hash_password(clean["password"]),
        "created_at": datetime.utcnow().isoformat()
    }

    users.append(new_user)
    save_json(USERS_PATH, users)

    return redirect(url_for("login", registered=1))


# ------------------------
# LOGOUT
# ------------------------
@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ------------------------
# DASHBOARD
# ------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    scans = load_json(SCANS_PATH)

    latest = scans[-1] if scans else None

    critical = 0
    if latest:
        critical = len([
            v for v in latest.get("vulnerabilities", [])
            if v.get("severity") == "Critical"
        ])

    return render_template(
        "dashboard/dashboard.html",
        scan=latest,
        critical_count=critical
    )


# ------------------------
# HISTORY
# ------------------------
@app.route("/history")
@login_required
def history():
    scans = load_json(SCANS_PATH)
    return render_template("dashboard/history.html", scans=scans)


# ------------------------
# SCAN DETAIL
# ------------------------
@app.route("/scan/<int:scan_id>")
@login_required
def scan_detail(scan_id):
    scans = load_json(SCANS_PATH)

    scan = next((s for s in scans if s["id"] == scan_id), None)
    if not scan:
        abort(404)

    return render_template("dashboard/scan_detail.html", scan=scan)


# ------------------------
# RUN SCAN (SIMULADO)
# ------------------------
@app.route("/scan/run", methods=["POST"])
@login_required
def run_scan():
    scans = load_json(SCANS_PATH)

    new_scan = {
        "id": len(scans) + 1,
        "date": datetime.utcnow().isoformat(),
        "risk_score": 78,
        "risk_level": "High",
        "vulnerabilities": [
            {
                "cve": "CVE-2024-9999",
                "package": "openssl",
                "severity": "Critical",
                "description": "Buffer overflow",
                "status": "Open"
            }
        ]
    }

    scans.append(new_scan)
    save_json(SCANS_PATH, scans)

    return redirect(url_for("dashboard"))


# ------------------------
if __name__ == "__main__":
    app.run(debug=True)