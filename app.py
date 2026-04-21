from flask import Flask, render_template, request, redirect, url_for, session
from datetime import datetime
import json
from pathlib import Path
from functools import wraps
import os
import uuid
import pyotp
import qrcode
import io
import base64

from encryption import (
    hash_password,
    verify_password,
    derive_user_key,
    encrypt_data,
    decrypt_data,
    encrypt_2fa_secret,
    decrypt_2fa_secret
)

from validation import validate_login_form, validate_register_form

from src.scanner_users import (
    run_pipaudit_scan,
    load_json_report,
    build_report,
    enrich_vulnerabilities
)

app = Flask(__name__)
app.secret_key = "dev-secret-change-me"

BASE_DIR = Path(__file__).resolve().parent
USERS_PATH = BASE_DIR / "data" / "users.json"


# ------------------------
# HELPERS
# ------------------------

def load_json(path):
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("[]", encoding="utf-8")
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def get_current_user():
    email = session.get("user_email")
    if not email:
        return None

    users = load_json(USERS_PATH)
    return next(
        (u for u in users if normalize_email(u["email"]) == normalize_email(email)),
        None
    )


# ------------------------
# SCANS
# ------------------------

def get_user_scans_dir(user_id):
    scans_dir = BASE_DIR / "data" / "scans" / str(user_id)
    scans_dir.mkdir(parents=True, exist_ok=True)
    return scans_dir


def load_user_scans(user_id):
    scans_dir = get_user_scans_dir(user_id)
    scans = []

    key_hex = session.get("enc_key")
    key = bytes.fromhex(key_hex) if key_hex else None

    for file in sorted(scans_dir.glob("scan_*.json")):
        try:
            raw = json.loads(file.read_text())

            if raw.get("encrypted") and key:
                scan = decrypt_data(raw["data"], key)
            else:
                scan = raw

            scan.setdefault("scan_id", file.stem.replace("scan_", ""))
            scans.append(scan)

        except:
            continue

    return scans


# ------------------------
# AUTH
# ------------------------

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not get_current_user():
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


# ------------------------
# ROUTES
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
        return render_template("auth/login.html", error="Invalid credentials", form={"email": email})

    email_norm = normalize_email(clean["email"])
    users = load_json(USERS_PATH)

    user = next((u for u in users if normalize_email(u["email"]) == email_norm), None)

    try:
        valid = user and verify_password(password, user["password"])
    except:
        valid = False

    if not valid:
        return render_template("auth/login.html", error="Invalid credentials", form={"email": email})

    # 🔐 SI TIENE 2FA
    if user.get("twofa_enabled"):
        session["tmp_user"] = email_norm
        session["tmp_password"] = password
        return redirect(url_for("verify_2fa"))

    # login normal
    session["user_email"] = email_norm
    session["user_id"] = user["id"]

    key = derive_user_key(password, user["password"]["salt"])
    session["enc_key"] = key.hex()

    return redirect(url_for("dashboard"))


# ------------------------
# VERIFY 2FA LOGIN
# ------------------------

@app.route("/2fa/verify", methods=["GET", "POST"])
def verify_2fa():
    if request.method == "GET":
        return render_template("auth/verify_2fa.html")

    code = request.form.get("code")

    email = session.get("tmp_user")
    password = session.get("tmp_password")

    users = load_json(USERS_PATH)
    user = next(u for u in users if u["email"] == email)

    secret = decrypt_2fa_secret(user["twofa_secret"])
    totp = pyotp.TOTP(secret)

    if not totp.verify(code):
        return render_template("auth/verify_2fa.html", error="Invalid code")

    # login final
    session["user_email"] = email
    session["user_id"] = user["id"]

    key = derive_user_key(password, user["password"]["salt"])
    session["enc_key"] = key.hex()

    session.pop("tmp_user", None)
    session.pop("tmp_password", None)

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
    phone = request.form.get("phone", "")
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")

    clean, errors = validate_register_form(full_name, email, phone, password, confirm)

    if errors:
        return render_template("auth/register.html", field_errors=errors, form=request.form)

    users = load_json(USERS_PATH)
    email_norm = normalize_email(clean["email"])

    if any(normalize_email(u["email"]) == email_norm for u in users):
        return render_template(
            "auth/register.html",
            field_errors={"email": "Email already registered"},
            form=request.form
        )

    new_id = str(uuid.uuid4())

    new_user = {
        "id": new_id,
        "full_name": clean["full_name"],
        "email": email_norm,
        "phone": clean["phone"],
        "password": hash_password(clean["password"]),
        "twofa_enabled": False,
        "twofa_secret": None,
        "created_at": datetime.utcnow().isoformat()
    }

    users.append(new_user)
    save_json(USERS_PATH, users)

    get_user_scans_dir(new_id)

    return redirect(url_for("login", registered=1))


# ------------------------
# 2FA SETUP
# ------------------------

@app.route("/2fa/setup")
@login_required
def setup_2fa():
    user = get_current_user()

    secret = pyotp.random_base32()
    session["temp_2fa_secret"] = secret

    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user["email"],
        issuer_name="DependencyScanner"
    )

    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()

    return render_template("auth/setup_2fa.html", qr=qr_base64)


@app.route("/2fa/verify-setup", methods=["POST"])
@login_required
def verify_2fa_setup():
    code = request.form.get("code")
    secret = session.get("temp_2fa_secret")

    if not secret:
        return redirect(url_for("dashboard"))

    totp = pyotp.TOTP(secret)

    if not totp.verify(code):
        return "Invalid code"

    users = load_json(USERS_PATH)
    user_id = session["user_id"]

    for u in users:
        if u["id"] == user_id:
            u["twofa_enabled"] = True
            u["twofa_secret"] = encrypt_2fa_secret(secret)

    save_json(USERS_PATH, users)

    session.pop("temp_2fa_secret", None)

    return redirect(url_for("dashboard"))


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
    user_id = session.get("user_id")
    scans = load_user_scans(user_id)

    scan_id = request.args.get("scan_id")
    selected_scan = None

    if scan_id:
        file = get_user_scans_dir(user_id) / f"scan_{scan_id}.json"

        if file.exists():
            raw = json.loads(file.read_text())
            key = bytes.fromhex(session["enc_key"])

            if raw.get("encrypted"):
                selected_scan = decrypt_data(raw["data"], key)
            else:
                selected_scan = raw

    if not selected_scan:
        selected_scan = scans[-1] if scans else None

    user = get_current_user()

    return render_template(
        "dashboard/dashboard.html",
        data=selected_scan,
        scans=scans,
        twofa_enabled=user.get("twofa_enabled", False)
    )

# ------------------------
# RUN SCAN
# ------------------------

@app.route("/scan/run", methods=["POST"])
@login_required
def run_scan():
    user_id = session.get("user_id")
    scans_dir = get_user_scans_dir(user_id)

    file = request.files.get("requirements_file")

    if not file or file.filename == "":
        return redirect(url_for("dashboard"))

    temp_path = BASE_DIR / f"temp_{user_id}_{file.filename}"
    file.save(temp_path)

    try:
        if file.filename.endswith(".json"):
            input_type = request.form.get("input_type", "pipaudit")
            vulnerabilities = load_json_report(str(temp_path), input_type)
        else:
            vulnerabilities = run_pipaudit_scan(str(temp_path))

        vulnerabilities = enrich_vulnerabilities(vulnerabilities)
        report = build_report(vulnerabilities)

        scan_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        report["scan_id"] = scan_id
        report["scan_date"] = datetime.utcnow().isoformat()

        key = bytes.fromhex(session["enc_key"])
        encrypted = encrypt_data(report, key)

        scan_file = scans_dir / f"scan_{scan_id}.json"
        scan_file.write_text(json.dumps({
            "encrypted": True,
            "data": encrypted
        }, indent=2))

    finally:
        if temp_path.exists():
            os.remove(temp_path)

    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=True)