#!/usr/bin/env python3
import eventlet
eventlet.monkey_patch()  # MUST be at the very top!

import os
import secrets
import logging
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

# ------------------------------
# Configuration and Setup
# ------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "prod_secret_key_change_me")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URI", "sqlite:///chat.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
socketio = SocketIO(app, cors_allowed_origins=["https://cryptoringtest.duckdns.org"])

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ------------------------------
# Database Models
# ------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))  # SQLAlchemy 2.0 approach

# ------------------------------
# Routes for Registration, Login, Logout, Search, and Chat
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
    # Generate a unique chat room name by sorting the two phone numbers
    room = "-".join(sorted([current_user.phone, phone]))
    return render_template("chat.html", room=room, other_phone=phone, user=current_user)

# ------------------------------
# New Endpoint: Handshake Using LWE-Beaver Integration
# ------------------------------
@app.route("/initiate_handshake/<recipient>")
@login_required
def initiate_handshake(recipient):
    """
    Demonstration endpoint using the experimental LWE-Beaver integration.
    For demonstration purposes, we generate a binary session key (0 or 1) and encrypt it.
    In a real deployment, a full symmetric key should be processed using hybrid encryption.
    """
    # Import the LWE-Beaver module
    from lwe_beaver import LWEBeaver
    lwe = LWEBeaver()  # In production, parameters and keys must be shared consistently!
    
    # Generate a binary session key (for demonstration)
    session_key = secrets.choice([0, 1])
    ciphertext = lwe.encrypt_session_key(session_key)
    
    # For demonstration, flash the ciphertext and the expected (original) session key.
    flash(f"Initiated handshake with recipient {recipient}. Encrypted ciphertext: {ciphertext}. (Original session key = {session_key})", "info")
    # In production, the ciphertext would be securely transmitted to the recipient who would decrypt it.
    return redirect(url_for("search"))

@app.route("/test_decrypt")
@login_required
def test_decrypt():
    """
    A test endpoint that encrypts and then immediately decrypts a binary session key
    using the same LWE-Beaver instance. This verifies that the encryption and decryption work.
    """
    from lwe_beaver import LWEBeaver
    lwe = LWEBeaver()
    session_key = secrets.choice([0, 1])
    ciphertext = lwe.encrypt_session_key(session_key)
    decrypted = lwe.decrypt_session_key(ciphertext)
    flash(f"Test Handshake: Original key = {session_key}, Decrypted key = {decrypted}", "info")
    return redirect(url_for("search"))

# ------------------------------
# Socket.IO Events for Real-Time Chat
# ------------------------------
@socketio.on("join")
def handle_join(data):
    room = data.get("room")
    if room:
        join_room(room)
        send({"msg": f"{current_user.phone} has entered the room."}, room=room)

@socketio.on("message")
def handle_message(data):
    room = data.get("room")
    msg = data.get("msg")
    if room and msg:
        send({"msg": f"{current_user.phone}: {msg}"}, room=room)

# ------------------------------
# Note: Do not call socketio.run() here.
# Production deployment is handled by Gunicorn with Eventlet.
# ------------------------------

#THESE 2 LINES ARE ONLY MEANT TO BE USED IN PRODUCTION
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    # For development testing only:
    socketio.run(app, host="127.0.0.1", port=8000, debug=True)
