#!/usr/bin/env python3
import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    current_user,
    logout_user
)
from flask_socketio import SocketIO, join_room, send
from werkzeug.security import generate_password_hash, check_password_hash
import os
import logging

# ------------------------------
# Configuration and Setup
# ------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev_secret_key_change_me")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URI", "sqlite:///chat.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
socketio = SocketIO(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ------------------------------
# Models
# ------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))  # Fixed for SQLAlchemy 2.0

# ------------------------------
# Routes
# ------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        phone = request.form.get("phone")
        password = request.form.get("password")
        if not phone or not password:
            flash("Please provide both phone number and password.", "error")
        elif User.query.filter_by(phone=phone).first():
            flash("This phone number is already registered.", "error")
        else:
            new_user = User(phone=phone, password=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful. Please log in.", "info")
            return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone = request.form.get("phone")
        password = request.form.get("password")
        user = User.query.filter_by(phone=phone).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("search"))
        else:
            flash("Invalid phone number or password.", "error")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("index"))

@app.route("/search", methods=["GET"])
@login_required
def search():
    query = request.args.get("q", "")
    results = []
    if query:
        results = User.query.filter(User.phone.contains(query)).all()
    return render_template("search.html", results=results, query=query)

@app.route("/chat/<phone>")
@login_required
def chat(phone):
    room = "-".join(sorted([current_user.phone, phone]))
    return render_template("chat.html", room=room, other_phone=phone, user=current_user)

# ------------------------------
# SocketIO Events
# ------------------------------
@socketio.on("join")
def on_join(data):
    room = data.get("room")
    if room:
        join_room(room)
        send({"msg": f"{current_user.phone} has entered the room."}, room=room)

@socketio.on("message")
def on_message(data):
    room = data.get("room")
    msg = data.get("msg")
    if room and msg:
        send({"msg": f"{current_user.phone}: {msg}"}, room=room)

# ------------------------------
# Main
# ------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    socketio.run(app, host="0.0.0.0", port=8000, debug=True)
