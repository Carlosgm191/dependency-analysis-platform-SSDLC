import re
import unicodedata
from typing import Tuple, Dict
from encryption import verify_password

EMAIL_BASIC_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
NAME_ALLOWED_RE = re.compile(r"^[A-Za-zÀ-ÖØ-öø-ÿ'\- ]+$")    
PHONE_RE = re.compile(r"^\d{7,15}$") 

def normalize_basic(value: str) -> str:

    return unicodedata.normalize("NFKC", (value or "")).strip()


def validate_full_name(name: str) -> Tuple[str, str]:

    name = normalize_basic(name)
    name = re.sub(r"\s+", " ", name)

    if not name:
        return "", "Full name is required"

    if (len(name) < 2 or len(name) > 60):
        return "", "Full name must be between 2 and 60 characters"

    if not NAME_ALLOWED_RE.match(name):
        return "", "Invalid characters in name"

    return name, ""

def validate_email(email: str) -> Tuple[str, str]:

    email = normalize_basic(email).lower()

    if not email:
        return "", "Email is required"

    if (len(email) > 254):
        return "", "Email too long"

    if not EMAIL_BASIC_RE.match(email):
        return "", "Invalid email format"

    return email, ""

def validate_phone(phone: str) -> Tuple[str, str]:

    phone = normalize_basic(phone)
    phone = phone.replace(" ", "")

    if not phone:
        return "", "Phone is required"

    if not PHONE_RE.match(phone):
        return "", "Phone must contain 7 to 15 digits"

    return phone, ""

def validate_password(password: str, email: str) -> Tuple[str, str]:

    password = normalize_basic(password)

    if (len(password) < 8 or len(password) > 64):
        return "", "Password must be between 8 and 64 characters."

    if " " in password:
        return "", "Password cannot contain spaces."

    if password.lower() == email.lower():
        return "", "Password cannot be equal to email."

    if not re.search(r"[A-Z]", password):
        return "", "Must include uppercase letter."

    if not re.search(r"[a-z]", password):
        return "", "Must include lowercase letter."

    if not re.search(r"[0-9]", password):
        return "", "Must include number."

    if not re.search(r"[!@#$%^&*()\-_=+\[\]{}<>?/]", password):
        return "", "Must include special character."

    return password, ""

def validate_password_confirmation(password: str, confirm: str) -> Tuple[str, str]:

    confirm = normalize_basic(confirm)

    if password != confirm:
        return "", "Passwords do not match"

    return "", ""

def validate_register_form(
    full_name: str,
    email: str,
    phone: str,
    password: str,
    confirm_password: str
) -> Tuple[Dict, Dict]:

    clean = {}
    errors = {}

    name_clean, err = validate_full_name(full_name)
    if err:
        errors["full_name"] = err
    clean["full_name"] = name_clean

    email_clean, err = validate_email(email)
    if err:
        errors["email"] = err
    clean["email"] = email_clean

    phone_clean, err = validate_phone(phone)
    if err:
        errors["phone"] = err
    clean["phone"] = phone_clean

    password_clean, err = validate_password(password, email)
    if err:
        errors["password"] = err
    clean["password"] = password_clean

    _, err = validate_password_confirmation(password, confirm_password)
    if err:
        errors["confirm_password"] = err

    return clean, errors

def validate_profile_form(
    full_name: str,
    phone: str,
    current_password: str,
    new_password: str,
    confirm_new_password: str,
    user_email: str,
    stored_password: str
) -> Tuple[Dict, Dict]:

    clean = {}
    errors = {}

    name_clean, err = validate_full_name(full_name)
    if err:
        errors["full_name"] = err
    clean["full_name"] = name_clean

    phone_clean, err = validate_phone(phone)
    if err:
        errors["phone"] = err
    clean["phone"] = phone_clean

    if new_password:
        current_password = normalize_basic(current_password)
        
        if not current_password:
            errors["current_password"] = "Current password is required"
        elif not verify_password(current_password, stored_password):
            errors["current_password"] = "Current password is incorrect"
        else:
            password_clean, err = validate_password(new_password, user_email)
            if err:
                errors["new_password"] = err
            clean["new_password"] = password_clean

            _, err = validate_password_confirmation(new_password, confirm_new_password)
            if err:
                errors["confirm_new_password"] = err

    return clean, errors

def validate_login_form(
    email: str,
    password: str
) -> Tuple[Dict, Dict]:

    clean = {}
    errors = {}

    email = normalize_basic(email)
    password = normalize_basic(password)

    if not email or not password:
        errors["general"] = "Invalid credentials"
        return clean, errors

    email_clean, err = validate_email(email)
    if err:
        errors["general"] = "Invalid credentials"
        return clean, errors

    clean["email"] = email_clean
    clean["password"] = password

    return clean, errors 