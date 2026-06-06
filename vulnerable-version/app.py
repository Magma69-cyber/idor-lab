from flask import Flask, request, session, redirect, url_for, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "super_insecure_secret_key_123"
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
            print("[*] Database seeded with alice, bob, charlie")


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
def profile(user_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    user = User.query.get(user_id)
    if not user:
        return "User not found", 404
    # ⚠️  No ownership check — any logged-in user can view any profile
    return render_template("profile.html",
                           user=user,
                           current_user_id=session["user_id"],
                           vulnerable=True)


# ─── VULNERABLE ENDPOINT ───────────────────────────────────────────────────────
#
#  🚨  IDOR HERE: No check that session["user_id"] == user_id
#      Any authenticated user can POST to /profile/1, /profile/2, etc.
#      and overwrite another user's data.
#
@app.route("/profile/<int:user_id>/update", methods=["POST"])
def update_profile(user_id):
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # ❌  MISSING: if session["user_id"] != user_id: return 403
    #     This is the IDOR vulnerability — object reference never validated against session owner

    user.username = request.form.get("username", user.username)
    user.email    = request.form.get("email",    user.email)
    user.bio      = request.form.get("bio",      user.bio)
    db.session.commit()

    return jsonify({
        "status":  "updated",
        "user_id": user_id,
        "note":    "⚠️ No ownership check performed — IDOR vulnerability present!"
    }), 200


@app.route("/users")
def list_users():
    """List all users — shows IDs to help demonstrate the attack."""
    if "user_id" not in session:
        return redirect(url_for("login"))
    users = User.query.all()
    return render_template("users.html", users=users)


if __name__ == "__main__":
    seed_db()
    print("\n[*] VULNERABLE version running at http://localhost:5000")
    print("[*] Seed accounts: alice/alice123  bob/bob123  charlie/charlie123\n")
    app.run(debug=True, port=5000)
