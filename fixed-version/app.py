from flask import Flask, request, session, redirect, url_for, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = "properly_managed_secret_key_env_var_in_prod"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# ─── Models ────────────────────────────────────────────────────────────────────

class User(db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email    = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    bio      = db.Column(db.String(300), default="No bio yet.")


# ─── Auth Decorator ─────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated


# ─── Seed Data ─────────────────────────────────────────────────────────────────

def seed_db():
    with app.app_context():
        db.create_all()
        if not User.query.first():
            users = [
                User(username="alice",   email="alice@lab.com",   bio="Admin of this platform.",       password=generate_password_hash("alice123")),
                User(username="bob",     email="bob@lab.com",     bio="Regular user. Loves security.",  password=generate_password_hash("bob123")),
                User(username="charlie", email="charlie@lab.com", bio="New user. Still learning.",      password=generate_password_hash("charlie123")),
            ]
            db.session.add_all(users)
            db.session.commit()


# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("profile", user_id=session["user_id"]))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["username"] = user.username
            return redirect(url_for("profile", user_id=user.id))
        error = "Invalid credentials."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/profile/<int:user_id>", methods=["GET"])
@login_required
def profile(user_id):
    user = User.query.get(user_id)
    if not user:
        return "User not found", 404
    return render_template("profile.html",
                           user=user,
                           current_user_id=session["user_id"],
                           vulnerable=False)


# ─── FIXED ENDPOINT ────────────────────────────────────────────────────────────
#
#  ✅  FIX: Ownership check — session["user_id"] must match the requested user_id
#      If not, return 403 Forbidden immediately.
#
@app.route("/profile/<int:user_id>/update", methods=["POST"])
@login_required
def update_profile(user_id):
    # ✅  AUTHORIZATION CHECK — The core IDOR fix
    if session["user_id"] != user_id:
        return jsonify({
            "error":   "403 Forbidden",
            "message": "You are not authorized to modify this resource.",
            "detail":  f"Your session belongs to user {session['user_id']}, "
                       f"but you attempted to modify user {user_id}."
        }), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Safe to update — caller owns this resource
    user.username = request.form.get("username", user.username)
    user.email    = request.form.get("email",    user.email)
    user.bio      = request.form.get("bio",      user.bio)
    db.session.commit()

    return jsonify({
        "status":  "updated",
        "user_id": user_id,
        "note":    "✅ Ownership validated — update allowed."
    }), 200


@app.route("/users")
@login_required
def list_users():
    users = User.query.all()
    return render_template("users.html", users=users)


if __name__ == "__main__":
    seed_db()
    print("\n[*] FIXED version running at http://localhost:5001")
    print("[*] Seed accounts: alice/alice123  bob/bob123  charlie/charlie123\n")
    app.run(debug=True, port=5001)
