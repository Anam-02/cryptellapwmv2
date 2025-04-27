from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, make_response
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from encryption import encrypt_password, decrypt_password
from datetime import datetime
from functools import wraps

routes = Blueprint('routes', __name__)

# -----------------------------
# Helper: Login Required Decorator
# -----------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session or (not session.get("verified") and "2fa_code" not in session):
            flash("Session expired or 2FA not completed")
            return redirect(url_for("routes.unlock"))

        user_id = session.get("user_id")
        response = make_response(f(*args, **kwargs))
        response.set_cookie("unlock_user_id", str(user_id), max_age=3600)
        return response

    return decorated_function

# =============================
#  HOME PAGE ROUTES
# =============================

# -----------------------------
# Route: / — Homepage (default entry point)
# -----------------------------
@routes.route("/")
def index():
    # Reset 2FA state if needed
    if "2fa_code" in session and not session.get("verified"):
        session.pop("2fa_code", None)

    return render_template("home.html")

# -----------------------------
# Route: /home — Alternate homepage (optional)
# -----------------------------
@routes.route("/home")
def home():
    return redirect(url_for("routes.index"))  # optional: just reuse "/" route



# =============================
#  AUTHENTICATION ROUTES
# =============================

# -----------------------------
# Route: /login — User login with optional 2FA
# -----------------------------
@routes.route("/login", methods=["GET", "POST"])
def login():
    # Redirect to vault if already logged in and verified
    if "user_id" in session and session.get("verified"):
        return redirect(url_for("routes.vault"))

    if request.method == "POST":
        email = request.form["login_username"]
        password = request.form["login_password"]

        # Connect to the database and fetch the user
        conn = sqlite3.connect("database/vaultt.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, fullname, password_hash, is_2fa_enabled FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()  # Fetch the user if exists
        conn.close()

        if user:
            user_id, fullname, hashed_pw, is_2fa_enabled = user

            # Check if password matches
            if check_password_hash(hashed_pw, password):
                # Start a session and store user info
                session.permanent = True
                session["user_id"] = user_id
                session["fullname"] = fullname
                session["verified"] = False  # User is not verified yet
                session.modified = True  # Ensure session is updated immediately

                # 2FA Flow (Only if 2FA is enabled)
                if is_2fa_enabled == 1:
                    # Generate a random 6-digit code
                    import random
                    code = random.randint(100000, 999999)
                    session["2fa_code"] = str(code)  # Store the code in session

                    flash("2FA code generated. Please proceed to the next page.")
                    print(f"[2FA CODE] Show this to user: {code}")

                    # Redirect to the page where the user will see the 2FA code
                    return redirect(url_for("routes.show_2fa_code"))

                # If 2FA is not enabled, allow normal login and direct to vault
                session["verified"] = True
                flash("Logged in successfully!")
                return redirect(url_for("routes.vault"))
            else:
                flash("Incorrect password.")
        else:
            flash("No account found with that email.")

    return render_template("login.html")


@routes.route("/show-2fa-code")
def show_2fa_code():
    # Check if the 2FA code exists in the session
    if "2fa_code" in session:
        code = session["2fa_code"]
        return render_template("show_2fa_code.html", code=code)

    # If the session has expired or no code is found, redirect to login
    flash("Session expired. Please log in again.")
    return redirect(url_for("routes.login"))



# -----------------------------
# Route: /signup — New user registration
# -----------------------------
@routes.route("/signup", methods=["GET", "POST"])
def signup():
    if "user_id" in session:
        return redirect(url_for("routes.vault"))

    if request.method == "POST":
        fullname = request.form.get("signup_fullname")
        email = request.form.get("signup_email")
        password = request.form.get("signup_password")
        confirm = request.form.get("signup_confirm")

        if password != confirm:
            flash("Passwords didn’t match. Try again.", "error")
            return redirect(url_for("routes.signup"))

        # Password Strength Check
        score = 0
        if len(password) >= 8:
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(not c.isalnum() for c in password):
            score += 1

        if score <= 1:
            flash("Password too weak! Please choose a stronger password.", "error")
            return redirect(url_for("routes.signup"))

        hashed_password = generate_password_hash(password)

        try:
            conn = sqlite3.connect("database/vaultt.db", timeout=5)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (fullname, email, password_hash, is_2fa_enabled) VALUES (?, ?, ?, ?)",
                (fullname, email, hashed_password, 0)
            )
            conn.commit()
            cursor.close()
            conn.close()

            flash("Account created! You can now log in.", "success")
            return redirect(url_for("routes.login"))

        except sqlite3.IntegrityError:
            flash("That email is already registered. Try logging in.", "error")
            return redirect(url_for("routes.signup"))

        except Exception:
            flash("Something went wrong. Please try again.", "error")
            return redirect(url_for("routes.signup"))

    return render_template("signup.html")





# -----------------------------
# Route: /verify — Two-Factor Authentication code entry
# -----------------------------
@routes.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "POST":
        entered_code = request.form.get("code")
        expected_code = session.get("2fa_code")

        if entered_code == expected_code:
            session["verified"] = True  # Mark the user as verified
            flash("2FA verified. You're in!")
            session.pop("2fa_code", None)  # Clear the 2FA code session data
            return redirect(url_for("routes.vault"))
        else:
            flash("Invalid code. Please try again.")

    return render_template("verify.html")





# -----------------------------
# Route: /logout — End user session
# -----------------------------
@routes.route("/logout")
def logout():
    # Clear session and return to homepage
    session.clear()
    flash("You’ve been logged out.")
    return redirect(url_for("routes.home"))


# -----------------------------
# Route: /unlock — Session re-authentication
# -----------------------------
@routes.route("/unlock", methods=["GET", "POST"])
def unlock():
    # Unlock session using saved cookie and re-entry of password
    user_id = request.cookies.get("unlock_user_id")

    if not user_id:
        flash("Session expired. Please log in again.")
        return redirect(url_for("routes.login"))

    if request.method == "POST":
        password = request.form.get("password")

        conn = sqlite3.connect("database/vaultt.db")
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[0], password):
            session["user_id"] = user_id
            session["verified"] = True
            session.modified = True

            resp = make_response(redirect(url_for("routes.vault")))
            resp.set_cookie("unlock_user_id", '', max_age=0)
            flash("Vault unlocked. Welcome back!")
            return resp
        else:
            flash("Invalid password.")

    return render_template("unlock.html")


# =============================
#  VAULT ROUTES
# =============================

# Route: /vault — Main dashboard after login
@routes.route('/vault', methods=["GET"])
@login_required
def vault():
    user_id = session["user_id"]
    fullname = session.get("fullname", "User")

    conn = sqlite3.connect("database/vaultt.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, account_name, username FROM vault WHERE user_id = ?", (user_id,))
    rows = cursor.fetchall()
    conn.close()

    entries = [{"id": row[0], "account_name": row[1], "username": row[2]} for row in rows]

    return render_template("vault.html", name=fullname, passwords=entries)


# Route: /passwords — List of saved password entries
@routes.route("/passwords", methods=["GET"])
@login_required
def passwords():
    user_id = session["user_id"]
    fullname = session.get("fullname", "User")

    conn = sqlite3.connect("database/vaultt.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, account_name, username FROM vault WHERE user_id = ?", (user_id,))
    rows = cursor.fetchall()
    conn.close()

    entries = [{"id": row[0], "account_name": row[1], "username": row[2]} for row in rows]

    return render_template("passwords.html", name=fullname, passwords=entries)


# Route: /add — Add new password entry (form + submit)
@routes.route("/add", methods=["GET", "POST"])
@login_required
def add_password():
    user_id = session["user_id"]

    if request.method == "POST":
        account_name = request.form["account_name"]
        username = request.form["username"]
        password = request.form["password"]

        encrypted_pw = encrypt_password(password)

        conn = sqlite3.connect("database/vaultt.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO vault (user_id, account_name, username, password_encrypted) VALUES (?, ?, ?, ?)",
            (user_id, account_name, username, encrypted_pw)
        )
        conn.commit()
        conn.close()

        flash("Password saved successfully!")
        return redirect(url_for("routes.passwords"))

    # Render the form if it's a GET request
    return render_template("add_password.html")



# Route: /delete/<id> — Delete a password entry
@routes.route("/delete/<int:entry_id>", methods=["GET"])
@login_required
def delete_password(entry_id):
    conn = sqlite3.connect("database/vaultt.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vault WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()

    flash("Password entry deleted.")
    return redirect(url_for("routes.passwords"))


# Route: /edit/<id> — Edit an existing password entry
@routes.route("/edit/<int:entry_id>", methods=["GET", "POST"])
@login_required
def edit_password(entry_id):
    user_id = session["user_id"]
    conn = sqlite3.connect("database/vaultt.db")
    cursor = conn.cursor()

    if request.method == "POST":
        updated_account_name = request.form["account_name"]
        updated_username = request.form["username"]
        updated_password = request.form["password"]
        encrypted_pw = encrypt_password(updated_password)

        cursor.execute("""
            UPDATE vault
            SET account_name = ?, username = ?, password_encrypted = ?
            WHERE id = ? AND user_id = ?
        """, (updated_account_name, updated_username, encrypted_pw, entry_id, user_id))
        conn.commit()
        conn.close()

        flash("Password updated successfully.")
        return redirect(url_for("routes.passwords"))

    cursor.execute("SELECT account_name, username FROM vault WHERE id = ? AND user_id = ?", (entry_id, user_id))
    row = cursor.fetchone()
    conn.close()

    if row:
        entry = {
            "id": entry_id,
            "account_name": row[0],
            "username": row[1]
        }
        return render_template("edit.html", entry=entry)
    else:
        flash("Entry not found.")
        return redirect(url_for("routes.passwords"))



# Route: /decrypt/<id> — Reveal a stored password (AJAX)
@routes.route("/decrypt/<int:entry_id>")
@login_required
def decrypt(entry_id):
    user_id = session["user_id"]
    conn = sqlite3.connect("database/vaultt.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password_encrypted FROM vault WHERE id = ? AND user_id = ?", (entry_id, user_id))
    row = cursor.fetchone()
    conn.close()

    if row:
        decrypted = decrypt_password(row[0])
        return jsonify({"password": decrypted})

    return jsonify({"error": "Not found"}), 404


# =============================
#  SETTINGS & ACCOUNT OPTIONS
# =============================

# Route: /settings — Account settings (2FA toggle, recovery email)
@routes.route("/settings")
@login_required
def settings():
    user_id = session["user_id"]
    conn = sqlite3.connect("database/vaultt.db")
    cursor = conn.cursor()
    cursor.execute("SELECT is_2fa_enabled FROM users WHERE id = ?", (user_id,))
    is_enabled = cursor.fetchone()[0]
    conn.close()

    return render_template("settings.html", is_2fa_enabled=is_enabled)


# Route: /toggle-2fa — Enable or disable 2FA
@routes.route("/toggle-2fa")
@login_required
def toggle_2fa():
    user_id = session["user_id"]
    conn = sqlite3.connect("database/vaultt.db")
    cursor = conn.cursor()

    cursor.execute("SELECT is_2fa_enabled FROM users WHERE id = ?", (user_id,))
    current = cursor.fetchone()[0]
    new_status = 0 if current else 1

    cursor.execute("UPDATE users SET is_2fa_enabled = ? WHERE id = ?", (new_status, user_id))
    conn.commit()
    conn.close()

    flash("2FA " + ("enabled." if new_status else "disabled."))
    return redirect(url_for("routes.settings"))



# =============================
#  PASSWORD RECOVERY ROUTES
# =============================

# Route: /recover — Start reset via email (console code)
@routes.route("/recover", methods=["GET", "POST"])
def recover():
    if request.method == "POST":
        email = request.form.get("email")

        conn = sqlite3.connect("database/vaultt.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user:
            import random
            code = random.randint(100000, 999999)
            session["reset_email"] = email
            session["reset_code"] = str(code)

            flash(f"Your password reset code is: {code}", "success")
            return redirect(url_for("routes.reset_password"))

        flash("No account found with that email.", "error")

    return render_template("recover.html")



# Route: /reset_password — Enter code + set new password
@routes.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    # Handle password reset using the code previously generated
    if request.method == "POST":
        code_entered = request.form.get("code")
        new_password = request.form.get("new_password")
        confirm = request.form.get("confirm")

        if code_entered != session.get("reset_code"):
            flash("Invalid reset code.")
            return redirect(url_for("routes.reset_password"))

        if new_password != confirm:
            flash("Passwords didn’t match.")
            return redirect(url_for("routes.reset_password"))

        hashed = generate_password_hash(new_password)
        email = session.get("reset_email")

        conn = sqlite3.connect("database/vaultt.db")
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password_hash = ? WHERE email = ?", (hashed, email))
        conn.commit()
        conn.close()

        session.pop("reset_email", None)
        session.pop("reset_code", None)

        flash("Password reset successful! You can log in now.")
        return redirect(url_for("routes.login"))

    return render_template("reset_password.html")


# Route: /add-recovery-email — Add or update a backup email
@routes.route("/add-recovery-email", methods=["GET", "POST"])
@login_required
def add_recovery_email():
    user_id = session["user_id"]

    if request.method == "POST":
        new_email = request.form.get("recovery_email")

        conn = sqlite3.connect("database/vaultt.db")
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET recovery_email = ? WHERE id = ?", (new_email, user_id))
        conn.commit()
        conn.close()

        flash("Recovery email updated!")
        return redirect(url_for("routes.settings"))

    return render_template("add_recovery_email.html")



# =============================
#  SESSION REFRESH HOOK
# =============================

# Refresh session timer on every user action
@routes.before_app_request
def check_session_timeout():
    if "user_id" in session:
        session.modified = True
