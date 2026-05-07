from flask import Flask, request, session, redirect, render_template, url_for
import sqlite3
import bcrypt
import pyotp
import qrcode
import os
import re
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret")

# -----------------------------
# SESSION SECURITY
# -----------------------------
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # True in production (HTTPS)
    SESSION_COOKIE_SAMESITE='Lax'
)

# -----------------------------
# DATABASE
# -----------------------------
def get_db():
    return sqlite3.connect("database.db")

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password_hash BLOB,
        twofa_secret TEXT,
        twofa_enabled INTEGER DEFAULT 0
    )
    """)
    conn.commit()
    conn.close()

init_db()

# -----------------------------
# VALIDATION
# -----------------------------
def validate_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email)

def validate_password(password):
    return (
        len(password) >= 8 and
        any(c.isdigit() for c in password) and
        any(c.isupper() for c in password)
    )

# -----------------------------
# PASSWORD HASHING
# -----------------------------
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

# -----------------------------
# LOGIN REQUIRED DECORATOR
# -----------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login-page')
        return f(*args, **kwargs)
    return wrapper

# -----------------------------
# HOME
# -----------------------------
@app.route('/')
def home():
    return redirect('/login-page')

# -----------------------------
# PAGES
# -----------------------------
@app.route('/login-page')
def login_page():
    return render_template('login.html')

@app.route('/register-page')
def register_page():
    return render_template('register.html')

# -----------------------------
# REGISTER
# -----------------------------
@app.route('/register', methods=['POST'])
def register():
    email = request.form.get("email")
    password = request.form.get("password")
    if not validate_email(email) or not validate_password(password):
        return "❌ Invalid email or weak password"

    hashed = hash_password(password)

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (email, hashed)
        )
        conn.commit()
        conn.close()
        return redirect('/login-page')
    except sqlite3.IntegrityError:
        return "❌ User already exists"

# -----------------------------
# LOGIN
# -----------------------------
@app.route('/login', methods=['POST'])
def login():
    email = request.form.get("email")
    password = request.form.get("password")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()

    if not user or not verify_password(password, user[2]):
        return "❌ Invalid credentials"

    if user[4] == 1:
        session['temp_user'] = user[0]
        return redirect('/2fa-page')

    session['user_id'] = user[0]
    return redirect('/dashboard')

# -----------------------------
# 2FA SETUP
# -----------------------------
@app.route('/setup-2fa')
@login_required
def setup_2fa():
    secret = pyotp.random_base32()

    otp_uri = pyotp.TOTP(secret).provisioning_uri(
        name="SecureApp",
        issuer_name="SecureLoginApp"
    )

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET twofa_secret=? WHERE id=?",
        (secret, session['user_id'])
    )
    conn.commit()
    conn.close()

    import base64
    from io import BytesIO

    img = qrcode.make(otp_uri)

    buffer = BytesIO()
    img.save(buffer, format="PNG")
    img_str = base64.b64encode(buffer.getvalue()).decode()

    return render_template("2fa.html", qr_code=img_str)
# -----------------------------
# 2FA PAGE
# -----------------------------
@app.route('/2fa-page')
def twofa_page():
    return '''
        <h2>Enter OTP</h2>
        <form method="POST" action="/verify-2fa">
            <input name="token" placeholder="Enter OTP">
            <button type="submit">Verify</button>
        </form>
    '''

# -----------------------------
# VERIFY 2FA
# -----------------------------
@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    token = request.form.get("token")

    user_id = session.get('temp_user')
    if not user_id:
        return "Unauthorized"

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT twofa_secret FROM users WHERE id=?",
        (user_id,)
    )
    result = cursor.fetchone()
    conn.close()

    if not result:
        return "2FA not setup"

    totp = pyotp.TOTP(result[0])

    if not totp.verify(token):
        return "❌ Invalid OTP"

    session['user_id'] = user_id
    session.pop('temp_user', None)

    return redirect('/dashboard')
# -----------------------------
# DASHBOARD (PROTECTED)
# -----------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# -----------------------------
# LOGOUT
# -----------------------------
@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect('/login-page')

# -----------------------------
# RUN
# -----------------------------
if __name__ == '__main__':
    app.run(debug=True)