from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import csv
import sqlite3
import os
import hashlib
import uuid
import base64
from datetime import datetime
from functools import wraps

app = Flask(__name__)
CORS(app)

# ─── Config ──────────────────────────────────────────────────────────────────────
DATA_FILE      = "vitals.csv"
DB_FILE        = "vitatrack.db"
UPLOADS_FOLDER = "uploads"
os.makedirs(UPLOADS_FOLDER, exist_ok=True)

# ─── Database setup ──────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    # Users table (medical personnel + admins)
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            TEXT PRIMARY KEY,
            full_name     TEXT NOT NULL,
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL,   -- 'admin', 'doctor', 'nurse', 'paramedic', 'other'
            post          TEXT,            -- e.g. "Senior Consultant", "Ward Nurse"
            passport_path TEXT,            -- path to uploaded passport image
            approved      INTEGER DEFAULT 0,  -- admin must approve non-admin users
            created_at    TEXT NOT NULL
        )
    """)

    # Patients table
    c.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            id            TEXT PRIMARY KEY,
            full_name     TEXT NOT NULL,
            date_of_birth TEXT,
            gender        TEXT,
            blood_group   TEXT,
            diagnosis     TEXT,
            notes         TEXT,
            device_id     TEXT,            -- linked device
            created_at    TEXT NOT NULL,
            created_by    TEXT             -- admin user id
        )
    """)

    # Devices table
    c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id            TEXT PRIMARY KEY,  -- unique device ID (e.g. VTDEV-0001)
            label         TEXT,
            patient_id    TEXT,              -- assigned patient (NULL if unassigned)
            registered_at TEXT NOT NULL,
            status        TEXT DEFAULT 'active'
        )
    """)

    # Patient assignments (which personnel are assigned to which patient)
    c.execute("""
        CREATE TABLE IF NOT EXISTS assignments (
            id          TEXT PRIMARY KEY,
            patient_id  TEXT NOT NULL,
            user_id     TEXT NOT NULL,
            assigned_at TEXT NOT NULL,
            assigned_by TEXT
        )
    """)

    # Create default admin if none exists
    admin_exists = c.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone()
    if not admin_exists:
        admin_id = str(uuid.uuid4())
        pw_hash  = hash_password("admin123")
        c.execute("""
            INSERT INTO users (id, full_name, email, password_hash, role, post, approved, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (admin_id, "System Admin", "admin@vitatrack.com", pw_hash,
              "admin", "System Administrator", 1, datetime.now().isoformat()))

    # Seed one device VTDEV-0001 if none exist
    dev_exists = c.execute("SELECT id FROM devices LIMIT 1").fetchone()
    if not dev_exists:
        c.execute("""
            INSERT INTO devices (id, label, patient_id, registered_at, status)
            VALUES (?, ?, ?, ?, ?)
        """, ("VTDEV-0001", "Primary Monitoring Unit", None,
              datetime.now().isoformat(), "active"))

    # Initialise vitals CSV
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp","Temperature","Blood Oxygen",
                             "Heart Rate","Respiration Rate","Blood Pressure","Device ID"])

    conn.commit()
    conn.close()

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

# ─── Auth helpers ────────────────────────────────────────────────────────────────
def verify_token(token):
    """Simple token = base64(user_id:email). Replace with JWT for production."""
    try:
        decoded = base64.b64decode(token).decode()
        user_id, email = decoded.split(":", 1)
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE id=? AND email=?",
                            (user_id, email)).fetchone()
        conn.close()
        return dict(user) if user else None
    except Exception:
        return None

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        user  = verify_token(token)
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        if not user["approved"]:
            return jsonify({"error": "Account pending approval"}), 403
        return f(user, *args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        user  = verify_token(token)
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        if user["role"] != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(user, *args, **kwargs)
    return decorated

# ═══════════════════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ═══════════════════════════════════════════════════════════════════════════════════

@app.route("/auth/signup", methods=["POST"])
def signup():
    """
    Accepts multipart/form-data with fields:
      full_name, email, password, role, post
    and optional file: passport
    """
    try:
        full_name = request.form.get("full_name", "").strip()
        email     = request.form.get("email", "").strip().lower()
        password  = request.form.get("password", "")
        role      = request.form.get("role", "nurse").strip()
        post      = request.form.get("post", "").strip()

        if not all([full_name, email, password, role]):
            return jsonify({"error": "Missing required fields"}), 400

        # Save passport image if provided
        passport_path = None
        if "passport" in request.files:
            file = request.files["passport"]
            if file.filename:
                ext  = os.path.splitext(file.filename)[1].lower()
                fname = f"{uuid.uuid4()}{ext}"
                passport_path = os.path.join(UPLOADS_FOLDER, fname)
                file.save(passport_path)

        user_id = str(uuid.uuid4())
        pw_hash = hash_password(password)
        # Admins are auto-approved; others need admin approval
        approved = 1 if role == "admin" else 0

        conn = get_db()
        try:
            conn.execute("""
                INSERT INTO users (id, full_name, email, password_hash, role, post,
                                   passport_path, approved, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (user_id, full_name, email, pw_hash, role, post,
                  passport_path, approved, datetime.now().isoformat()))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({"error": "Email already registered"}), 409
        conn.close()

        return jsonify({
            "message": "Account created. Awaiting admin approval." if not approved else "Admin account created.",
            "approved": bool(approved)
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/auth/login", methods=["POST"])
def login():
    data  = request.get_json()
    email = data.get("email", "").strip().lower()
    pw    = data.get("password", "")

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "Invalid email or password"}), 401
    if user["password_hash"] != hash_password(pw):
        return jsonify({"error": "Invalid email or password"}), 401
    if not user["approved"]:
        return jsonify({"error": "Account pending admin approval"}), 403

    token = base64.b64encode(f"{user['id']}:{user['email']}".encode()).decode()

    # Build passport URL
    passport_url = None
    if user["passport_path"] and os.path.exists(user["passport_path"]):
        passport_url = f"/users/{user['id']}/passport"

    return jsonify({
        "token":        token,
        "user_id":      user["id"],
        "full_name":    user["full_name"],
        "email":        user["email"],
        "role":         user["role"],
        "post":         user["post"],
        "passport_url": passport_url
    }), 200


@app.route("/users/<user_id>/passport", methods=["GET"])
def get_passport(user_id):
    conn = get_db()
    user = conn.execute("SELECT passport_path FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    if user and user["passport_path"] and os.path.exists(user["passport_path"]):
        return send_file(user["passport_path"])
    return jsonify({"error": "Not found"}), 404

# ═══════════════════════════════════════════════════════════════════════════════════
# ADMIN ROUTES
# ═══════════════════════════════════════════════════════════════════════════════════

@app.route("/admin/users", methods=["GET"])
@require_admin
def list_users(admin):
    conn  = get_db()
    users = conn.execute("SELECT id, full_name, email, role, post, approved, created_at FROM users").fetchall()
    conn.close()
    return jsonify([dict(u) for u in users]), 200


@app.route("/admin/users/<user_id>/approve", methods=["POST"])
@require_admin
def approve_user(admin, user_id):
    conn = get_db()
    conn.execute("UPDATE users SET approved=1 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "User approved"}), 200


@app.route("/admin/users/<user_id>/reject", methods=["DELETE"])
@require_admin
def reject_user(admin, user_id):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id=? AND role != 'admin'", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "User removed"}), 200


# ─── Patients ──────────────────────────────────────────────────────────────────

@app.route("/admin/patients", methods=["GET"])
@require_auth
def list_patients(user):
    conn     = get_db()
    patients = conn.execute("SELECT * FROM patients").fetchall()
    conn.close()
    return jsonify([dict(p) for p in patients]), 200


@app.route("/admin/patients", methods=["POST"])
@require_admin
def create_patient(admin):
    data = request.get_json()
    required = ["full_name"]
    if not all(data.get(k) for k in required):
        return jsonify({"error": "full_name is required"}), 400

    patient_id = str(uuid.uuid4())
    conn = get_db()
    conn.execute("""
        INSERT INTO patients (id, full_name, date_of_birth, gender, blood_group,
                              diagnosis, notes, device_id, created_at, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (patient_id, data["full_name"], data.get("date_of_birth"),
          data.get("gender"), data.get("blood_group"), data.get("diagnosis"),
          data.get("notes"), data.get("device_id"),
          datetime.now().isoformat(), admin["id"]))
    conn.commit()
    conn.close()
    return jsonify({"message": "Patient created", "patient_id": patient_id}), 201


@app.route("/admin/patients/<patient_id>", methods=["PUT"])
@require_admin
def update_patient(admin, patient_id):
    data = request.get_json()
    conn = get_db()
    conn.execute("""
        UPDATE patients SET full_name=?, date_of_birth=?, gender=?, blood_group=?,
            diagnosis=?, notes=?, device_id=?
        WHERE id=?
    """, (data.get("full_name"), data.get("date_of_birth"), data.get("gender"),
          data.get("blood_group"), data.get("diagnosis"), data.get("notes"),
          data.get("device_id"), patient_id))
    conn.commit()
    conn.close()
    return jsonify({"message": "Patient updated"}), 200


# ─── Devices ───────────────────────────────────────────────────────────────────

@app.route("/admin/devices", methods=["GET"])
@require_auth
def list_devices(user):
    conn    = get_db()
    devices = conn.execute("""
        SELECT d.*, p.full_name as patient_name
        FROM devices d
        LEFT JOIN patients p ON d.patient_id = p.id
    """).fetchall()
    conn.close()
    return jsonify([dict(d) for d in devices]), 200


@app.route("/admin/devices", methods=["POST"])
@require_admin
def add_device(admin):
    data      = request.get_json()
    device_id = data.get("device_id", "").strip().upper()
    if not device_id:
        return jsonify({"error": "device_id required"}), 400
    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO devices (id, label, patient_id, registered_at, status)
            VALUES (?, ?, ?, ?, ?)
        """, (device_id, data.get("label", ""), data.get("patient_id"),
              datetime.now().isoformat(), "active"))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Device ID already exists"}), 409
    conn.close()
    return jsonify({"message": "Device registered"}), 201


@app.route("/admin/devices/<device_id>/assign", methods=["POST"])
@require_admin
def assign_device(admin, device_id):
    data       = request.get_json()
    patient_id = data.get("patient_id")
    conn = get_db()
    conn.execute("UPDATE devices SET patient_id=? WHERE id=?", (patient_id, device_id))
    if patient_id:
        conn.execute("UPDATE patients SET device_id=? WHERE id=?", (device_id, patient_id))
    conn.commit()
    conn.close()
    return jsonify({"message": "Device assigned"}), 200


# ─── Assignments (personnel → patient) ────────────────────────────────────────

@app.route("/admin/assignments", methods=["POST"])
@require_admin
def assign_personnel(admin):
    data       = request.get_json()
    patient_id = data.get("patient_id")
    user_id    = data.get("user_id")
    if not patient_id or not user_id:
        return jsonify({"error": "patient_id and user_id required"}), 400

    conn = get_db()
    exists = conn.execute("SELECT id FROM assignments WHERE patient_id=? AND user_id=?",
                          (patient_id, user_id)).fetchone()
    if exists:
        conn.close()
        return jsonify({"message": "Already assigned"}), 200

    conn.execute("""
        INSERT INTO assignments (id, patient_id, user_id, assigned_at, assigned_by)
        VALUES (?, ?, ?, ?, ?)
    """, (str(uuid.uuid4()), patient_id, user_id,
          datetime.now().isoformat(), admin["id"]))
    conn.commit()
    conn.close()
    return jsonify({"message": "Personnel assigned to patient"}), 201


@app.route("/admin/assignments/<patient_id>", methods=["GET"])
@require_auth
def get_assignments(user, patient_id):
    conn = get_db()
    rows = conn.execute("""
        SELECT u.id, u.full_name, u.role, u.post, a.assigned_at
        FROM assignments a
        JOIN users u ON a.user_id = u.id
        WHERE a.patient_id = ?
    """, (patient_id,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows]), 200

# ═══════════════════════════════════════════════════════════════════════════════════
# VITALS ROUTES (unchanged + device_id support)
# ═══════════════════════════════════════════════════════════════════════════════════

@app.route("/data", methods=["POST"])
def receive_data():
    try:
        data             = request.get_json()
        temperature      = data.get("temperature")
        blood_oxygen     = data.get("blood_oxygen")
        heart_rate       = data.get("heart_rate")
        respiration_rate = data.get("respiration_rate")
        blood_pressure   = data.get("blood_pressure")
        device_id        = data.get("device_id", "VTDEV-0001")
        timestamp        = datetime.now().isoformat()

        with open(DATA_FILE, mode='a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, temperature, blood_oxygen,
                             heart_rate, respiration_rate, blood_pressure, device_id])

        return jsonify({"message": "Data received successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/vitals", methods=["GET"])
def get_vitals():
    try:
        device_id = request.args.get("device_id")
        if not os.path.exists(DATA_FILE):
            return jsonify({"error": "No data available"}), 404

        if device_id:
            import pandas as pd
            df = pd.read_csv(DATA_FILE)
            df = df[df["Device ID"] == device_id]
            return df.to_csv(index=False), 200, {"Content-Type": "text/csv"}

        return send_file(DATA_FILE, mimetype='text/csv')
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
