"""
VitaTrack Flask Backend
- PostgreSQL for all persistence (users, patients, devices, vitals)
- Photos stored as bytea in DB (no filesystem dependency)
- Compatible with Render.com free PostgreSQL add-on
"""

from flask import Flask, request, jsonify, send_file, Response
from datetime import datetime
import os, hashlib, uuid, io, base64
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

# ─── DB connection ────────────────────────────────────────────────────────────────
# Neon (and most hosted PostgreSQL) provides URLs starting with "postgres://"
# but psycopg2 requires "postgresql://" — fix that automatically.
_raw_db_url = os.environ.get("DATABASE_URL", "")
if not _raw_db_url:
    raise RuntimeError(
        "\n\n*** DATABASE_URL environment variable is not set! ***\n"
        "Get your connection string from neon.tech → your project → "
        "Connection string (Pooled connection) and add it as DATABASE_URL "
        "in your Render Flask service → Environment.\n"
    )
DATABASE_URL = _raw_db_url.replace("postgres://", "postgresql://", 1)

def get_db():
    """
    Connect using the full DATABASE_URL as-is.
    Neon URLs already contain ?sslmode=require so we must NOT also pass
    sslmode as a keyword argument — psycopg2 treats the two sources as
    conflicting and falls back to a localhost connection instead of
    using the URL. Let the URL carry all connection parameters.
    """
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn

# ─── Schema init ─────────────────────────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    full_name   TEXT NOT NULL,
    email       TEXT UNIQUE NOT NULL,
    password    TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'staff',
    post        TEXT NOT NULL,
    photo       BYTEA,
    approved    BOOLEAN DEFAULT FALSE,
    created_at  TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS patients (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    age         INTEGER,
    gender      TEXT,
    diagnosis   TEXT,
    notes       TEXT,
    device_id   TEXT,
    created_at  TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS patient_staff (
    patient_id  TEXT REFERENCES patients(id) ON DELETE CASCADE,
    staff_id    TEXT REFERENCES users(id)    ON DELETE CASCADE,
    PRIMARY KEY (patient_id, staff_id)
);

CREATE TABLE IF NOT EXISTS devices (
    device_id   TEXT PRIMARY KEY,
    label       TEXT,
    patient_id  TEXT REFERENCES patients(id) ON DELETE SET NULL,
    active      BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vitals (
    id                SERIAL PRIMARY KEY,
    timestamp         TIMESTAMP DEFAULT NOW(),
    temperature       FLOAT,
    blood_oxygen      FLOAT,
    heart_rate        FLOAT,
    respiration_rate  FLOAT,
    blood_pressure    TEXT,
    device_id         TEXT
);
"""

def init_db():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(SCHEMA)

    # Seed default admin if not exists
    cur.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
    if not cur.fetchone():
        uid = str(uuid.uuid4())
        pw  = hashlib.sha256("admin123".encode()).hexdigest()
        cur.execute("""
            INSERT INTO users (id, full_name, email, password, role, post, approved)
            VALUES (%s, %s, %s, %s, %s, %s, TRUE)
        """, (uid, "System Admin", "admin@vitatrack.com", pw, "admin", "Administrator"))

    # Seed default developer if not exists
    cur.execute("SELECT id FROM users WHERE role = 'developer' LIMIT 1")
    if not cur.fetchone():
        uid = str(uuid.uuid4())
        pw  = hashlib.sha256("dev123".encode()).hexdigest()
        cur.execute("""
            INSERT INTO users (id, full_name, email, password, role, post, approved)
            VALUES (%s, %s, %s, %s, %s, %s, TRUE)
        """, (uid, "Lead Developer", "dev@vitatrack.com", pw, "developer", "Developer"))

    conn.commit()
    cur.close()
    conn.close()

# Run schema init on startup
try:
    init_db()
except Exception as e:
    print(f"DB init warning: {e}")


def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════════
# DEBUG — visit /debug in browser to diagnose connection issues
# Remove this route once everything is working
# ══════════════════════════════════════════════════════════════════════════════════

@app.route('/debug', methods=['GET'])
def debug():
    import re
    raw = os.environ.get("DATABASE_URL", "")

    # Mask the password so credentials aren't exposed
    masked = re.sub(r'(:)([^@]+)(@)', r'\1****\3', raw) if raw else "NOT SET"

    result = {
        "DATABASE_URL_set": bool(raw),
        "DATABASE_URL_masked": masked,
        "starts_with_postgres": raw.startswith("postgres"),
        "after_prefix_fix": raw.replace("postgres://", "postgresql://", 1)[:40] + "..." if raw else "N/A",
    }

    # Try actually connecting
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("SELECT version()")
        version = cur.fetchone()
        cur.close()
        conn.close()
        result["connection"] = "SUCCESS"
        result["pg_version"]  = str(version)
    except Exception as e:
        result["connection"] = "FAILED"
        result["error"]      = str(e)

    return jsonify(result), 200


# ══════════════════════════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════════════════════════

@app.route('/auth/signup', methods=['POST'])
def signup():
    try:
        data      = request.get_json()
        full_name = data.get('full_name', '').strip()
        email     = data.get('email', '').strip().lower()
        password  = data.get('password', '')
        post      = data.get('post', '')
        photo_b64 = data.get('photo_b64')

        if not all([full_name, email, password, post]):
            return jsonify({"error": "All fields are required."}), 400

        photo_bytes = base64.b64decode(photo_b64) if photo_b64 else None
        uid = str(uuid.uuid4())

        conn = get_db(); cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO users (id, full_name, email, password, role, post, photo, approved)
                VALUES (%s, %s, %s, %s, 'staff', %s, %s, FALSE)
            """, (uid, full_name, email, hash_pw(password), post,
                  psycopg2.Binary(photo_bytes) if photo_bytes else None))
            conn.commit()
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            return jsonify({"error": "Email already registered."}), 409
        finally:
            cur.close(); conn.close()

        return jsonify({"message": "Account created. Awaiting admin approval.", "id": uid}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/auth/verify', methods=['POST'])
def verify_session():
    """
    Called by Streamlit on page refresh to validate a stored cookie.
    Accepts a user_id and returns the fresh user record if still valid and approved.
    """
    try:
        data    = request.get_json()
        user_id = data.get('user_id')
        if not user_id:
            return jsonify({"error": "user_id required"}), 400

        conn = get_db(); cur = conn.cursor()
        cur.execute(
            "SELECT id, full_name, email, role, post, approved, created_at FROM users WHERE id = %s",
            (user_id,)
        )
        user = cur.fetchone()
        cur.close(); conn.close()

        if not user:
            return jsonify({"error": "User not found"}), 404
        if not user['approved']:
            return jsonify({"error": "Account not approved"}), 403

        safe = dict(user)
        if safe.get('created_at'):
            safe['created_at'] = safe['created_at'].isoformat()
        return jsonify({"user": safe}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/auth/login', methods=['POST'])
def login():
    try:
        data  = request.get_json()
        email = data.get('email', '').strip().lower()
        pw    = data.get('password', '')

        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close(); conn.close()

        if not user:
            return jsonify({"error": "Invalid email or password."}), 401
        if user['password'] != hash_pw(pw):
            return jsonify({"error": "Invalid email or password."}), 401
        if not user['approved']:
            return jsonify({"error": "Account pending admin approval."}), 403

        safe = {k: v for k, v in user.items() if k not in ('password', 'photo')}
        # Convert datetime to string
        if safe.get('created_at'):
            safe['created_at'] = safe['created_at'].isoformat()
        return jsonify({"message": "Login successful.", "user": safe}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/auth/photo/<user_id>', methods=['GET'])
def get_photo(user_id):
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT photo FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        cur.close(); conn.close()
        if not row or not row['photo']:
            return jsonify({"error": "No photo"}), 404
        return Response(bytes(row['photo']), mimetype='image/jpeg')
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════════
# ADMIN — USERS
# ══════════════════════════════════════════════════════════════════════════════════

@app.route('/admin/users', methods=['GET'])
def list_users():
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT id, full_name, email, role, post, approved, created_at FROM users ORDER BY created_at DESC")
    rows = cur.fetchall()
    cur.close(); conn.close()
    result = []
    for r in rows:
        d = dict(r)
        if d.get('created_at'):
            d['created_at'] = d['created_at'].isoformat()
        result.append(d)
    return jsonify(result), 200


@app.route('/admin/approve/<user_id>', methods=['POST'])
def approve_user(user_id):
    conn = get_db(); cur = conn.cursor()
    cur.execute("UPDATE users SET approved = TRUE WHERE id = %s", (user_id,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"message": "User approved."}), 200


@app.route('/admin/reject/<user_id>', methods=['DELETE'])
def reject_user(user_id):
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"message": "User removed."}), 200


# ══════════════════════════════════════════════════════════════════════════════════
# ADMIN — PATIENTS
# ══════════════════════════════════════════════════════════════════════════════════

def get_patients_with_staff(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM patients ORDER BY created_at DESC")
    patients = [dict(r) for r in cur.fetchall()]
    for p in patients:
        if p.get('created_at'):
            p['created_at'] = p['created_at'].isoformat()
        cur.execute("""
            SELECT u.id, u.full_name, u.post FROM users u
            JOIN patient_staff ps ON u.id = ps.staff_id
            WHERE ps.patient_id = %s
        """, (p['id'],))
        p['assigned_to'] = [dict(r) for r in cur.fetchall()]
    cur.close()
    return patients


@app.route('/admin/patients', methods=['GET'])
def list_patients():
    conn = get_db()
    result = get_patients_with_staff(conn)
    conn.close()
    return jsonify(result), 200


@app.route('/admin/patients', methods=['POST'])
def create_patient():
    try:
        data = request.get_json()
        if not all([data.get('name'), data.get('diagnosis')]):
            return jsonify({"error": "name and diagnosis are required."}), 400
        pid = str(uuid.uuid4())
        conn = get_db(); cur = conn.cursor()
        cur.execute("""
            INSERT INTO patients (id, name, age, gender, diagnosis, notes)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (pid, data['name'], data.get('age'), data.get('gender'),
              data['diagnosis'], data.get('notes', '')))
        conn.commit()
        cur.execute("SELECT * FROM patients WHERE id = %s", (pid,))
        patient = dict(cur.fetchone())
        if patient.get('created_at'):
            patient['created_at'] = patient['created_at'].isoformat()
        patient['assigned_to'] = []
        cur.close(); conn.close()
        return jsonify({"message": "Patient created.", "patient": patient}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/admin/patients/<patient_id>', methods=['PUT'])
def update_patient(patient_id):
    try:
        data = request.get_json()
        conn = get_db(); cur = conn.cursor()
        fields = []
        values = []
        for col in ['name','age','gender','diagnosis','notes','device_id']:
            if col in data:
                fields.append(f"{col} = %s")
                values.append(data[col])
        if fields:
            values.append(patient_id)
            cur.execute(f"UPDATE patients SET {', '.join(fields)} WHERE id = %s", values)
        conn.commit(); cur.close(); conn.close()
        return jsonify({"message": "Patient updated."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/admin/patients/<patient_id>', methods=['DELETE'])
def delete_patient(patient_id):
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM patients WHERE id = %s", (patient_id,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"message": "Patient deleted."}), 200


@app.route('/admin/assign_staff', methods=['POST'])
def assign_staff():
    try:
        data       = request.get_json()
        patient_id = data.get('patient_id')
        staff_ids  = data.get('staff_ids', [])
        conn = get_db(); cur = conn.cursor()
        cur.execute("DELETE FROM patient_staff WHERE patient_id = %s", (patient_id,))
        for sid in staff_ids:
            cur.execute("INSERT INTO patient_staff (patient_id, staff_id) VALUES (%s, %s)",
                        (patient_id, sid))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"message": "Staff assigned."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════════
# ADMIN — DEVICES
# ══════════════════════════════════════════════════════════════════════════════════

@app.route('/admin/devices', methods=['GET'])
def list_devices():
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM devices ORDER BY created_at DESC")
    rows = [dict(r) for r in cur.fetchall()]
    for r in rows:
        if r.get('created_at'):
            r['created_at'] = r['created_at'].isoformat()
    cur.close(); conn.close()
    return jsonify(rows), 200


@app.route('/admin/devices', methods=['POST'])
def create_device():
    try:
        data   = request.get_json()
        dev_id = data.get('device_id', '').strip()
        label  = data.get('label', '')
        if not dev_id:
            return jsonify({"error": "device_id required."}), 400
        conn = get_db(); cur = conn.cursor()
        try:
            cur.execute("INSERT INTO devices (device_id, label) VALUES (%s, %s)", (dev_id, label))
            conn.commit()
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            return jsonify({"error": "Device ID already exists."}), 409
        finally:
            cur.close(); conn.close()
        return jsonify({"message": "Device registered."}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/admin/devices/assign', methods=['POST'])
def assign_device():
    try:
        data       = request.get_json()
        device_id  = data.get('device_id')
        patient_id = data.get('patient_id')
        conn = get_db(); cur = conn.cursor()
        # Clear old assignment
        cur.execute("UPDATE patients SET device_id = NULL WHERE device_id = %s", (device_id,))
        cur.execute("UPDATE devices  SET patient_id = %s WHERE device_id = %s", (patient_id, device_id))
        cur.execute("UPDATE patients SET device_id  = %s WHERE id = %s",        (device_id, patient_id))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"message": "Device assigned."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════════
# VITALS
# ══════════════════════════════════════════════════════════════════════════════════

@app.route('/data', methods=['POST'])
def receive_data():
    try:
        data = request.get_json()
        conn = get_db(); cur = conn.cursor()
        cur.execute("""
            INSERT INTO vitals
                (temperature, blood_oxygen, heart_rate, respiration_rate, blood_pressure, device_id)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            data.get('temperature'),
            data.get('blood_oxygen'),
            data.get('heart_rate'),
            data.get('respiration_rate'),
            data.get('blood_pressure'),
            data.get('device_id', 'UNKNOWN')
        ))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"message": "Data received successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/vitals', methods=['GET'])
def get_vitals():
    """Return vitals as CSV. Optional ?device_id=XXX filter."""
    try:
        device_filter = request.args.get('device_id')
        conn = get_db(); cur = conn.cursor()
        if device_filter:
            cur.execute("""
                SELECT timestamp AS "Timestamp",
                       temperature AS "Temperature",
                       blood_oxygen AS "Blood Oxygen",
                       heart_rate AS "Heart Rate",
                       respiration_rate AS "Respiration Rate",
                       blood_pressure AS "Blood Pressure",
                       device_id AS "Device ID"
                FROM vitals WHERE device_id = %s ORDER BY timestamp
            """, (device_filter,))
        else:
            cur.execute("""
                SELECT timestamp AS "Timestamp",
                       temperature AS "Temperature",
                       blood_oxygen AS "Blood Oxygen",
                       heart_rate AS "Heart Rate",
                       respiration_rate AS "Respiration Rate",
                       blood_pressure AS "Blood Pressure",
                       device_id AS "Device ID"
                FROM vitals ORDER BY timestamp
            """)
        rows = cur.fetchall()
        cur.close(); conn.close()

        if not rows:
            return jsonify({"error": "No data available"}), 404

        output = io.StringIO()
        import csv as csv_mod
        writer = csv_mod.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        for row in rows:
            d = dict(row)
            if hasattr(d.get('Timestamp'), 'isoformat'):
                d['Timestamp'] = d['Timestamp'].isoformat()
            writer.writerow(d)
        return Response(output.getvalue(), mimetype='text/csv')
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
