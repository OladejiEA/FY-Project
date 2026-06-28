"""
VitaTrack Flask Backend
- PostgreSQL for all persistence (users, patients, devices, vitals, alerts, calibration)
- Photos stored as bytea in DB
- Compatible with Render.com free PostgreSQL add-on
- Device ID whitelist removed — accepts any non-empty device_id
- Calibration stored per device per parameter; applied at display layer (Streamlit)
- Temperature back-filled from latest reading when hub sends N/A
"""

from flask import Flask, request, jsonify, Response
from datetime import datetime
import os, hashlib, uuid, io, base64, csv as csv_mod, time
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

# ── Simple in-memory throttle for frequently-polled GET endpoints ─────────────
_last_request_time = {}
THROTTLE_SECONDS   = 2

def throttle_check():
    ip  = request.remote_addr or "unknown"
    key = f"{ip}:{request.path}"
    now = time.time()
    last = _last_request_time.get(key, 0)
    if now - last < THROTTLE_SECONDS:
        return jsonify({"error": "Too many requests"}), 429
    _last_request_time[key] = now
    return None

@app.before_request
def before_request():
    if request.method == "GET" and request.path in ("/alerts", "/vitals", "/latest_vitals"):
        result = throttle_check()
        if result:
            return result

# ── Global error handlers ─────────────────────────────────────────────────────
@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad request", "detail": str(e)}), 400

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error", "detail": str(e)}), 500

# ── DB ────────────────────────────────────────────────────────────────────────
_raw_db_url = os.environ.get("DATABASE_URL", "")
if not _raw_db_url:
    raise RuntimeError("DATABASE_URL is not set.")
DATABASE_URL = _raw_db_url.replace("postgres://", "postgresql://", 1)

def get_db():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

# ── Schema ────────────────────────────────────────────────────────────────────
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

CREATE TABLE IF NOT EXISTS alerts (
    id          SERIAL PRIMARY KEY,
    message     TEXT NOT NULL,
    timestamp   TIMESTAMP DEFAULT NOW(),
    dismissed   BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS case_notes (
    id               SERIAL PRIMARY KEY,
    patient_id       TEXT REFERENCES patients(id) ON DELETE CASCADE,
    staff_id         TEXT REFERENCES users(id) ON DELETE SET NULL,
    staff_name       TEXT NOT NULL,
    note             TEXT NOT NULL,
    severity         TEXT DEFAULT 'Routine',
    vitals_snapshot  TEXT,
    created_at       TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS calibration (
    id          SERIAL PRIMARY KEY,
    device_id   TEXT NOT NULL,
    parameter   TEXT NOT NULL,
    gain        FLOAT DEFAULT 1.0,
    offset      FLOAT DEFAULT 0.0,
    updated_at  TIMESTAMP DEFAULT NOW(),
    UNIQUE (device_id, parameter)
);
"""

def init_db():
    conn = get_db(); cur = conn.cursor()
    cur.execute(SCHEMA)
    cur.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
    if not cur.fetchone():
        uid = str(uuid.uuid4())
        pw  = hashlib.sha256("admin123".encode()).hexdigest()
        cur.execute("""INSERT INTO users (id, full_name, email, password, role, post, approved)
            VALUES (%s, %s, %s, %s, %s, %s, TRUE)""",
            (uid, "System Admin", "admin@vitatrack.com", pw, "admin", "Administrator"))
    cur.execute("SELECT id FROM users WHERE role = 'developer' LIMIT 1")
    if not cur.fetchone():
        uid = str(uuid.uuid4())
        pw  = hashlib.sha256("dev123".encode()).hexdigest()
        cur.execute("""INSERT INTO users (id, full_name, email, password, role, post, approved)
            VALUES (%s, %s, %s, %s, %s, %s, TRUE)""",
            (uid, "Lead Developer", "dev@vitatrack.com", pw, "developer", "Developer"))
    conn.commit(); cur.close(); conn.close()

try:
    init_db()
except Exception as e:
    print(f"DB init warning: {e}")

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════════════════════

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
            cur.execute("""INSERT INTO users (id, full_name, email, password, role, post, photo, approved)
                VALUES (%s, %s, %s, %s, 'staff', %s, %s, FALSE)""",
                (uid, full_name, email, hash_pw(password), post,
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
    try:
        data    = request.get_json()
        user_id = data.get('user_id')
        if not user_id:
            return jsonify({"error": "user_id required"}), 400
        conn = get_db(); cur = conn.cursor()
        cur.execute(
            "SELECT id, full_name, email, role, post, approved, created_at FROM users WHERE id = %s",
            (user_id,))
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


# ══════════════════════════════════════════════════════════════════════════════
# ADMIN — USERS
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/admin/users', methods=['GET'])
def list_users():
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT id, full_name, email, role, post, approved, created_at FROM users ORDER BY created_at DESC")
    rows = cur.fetchall(); cur.close(); conn.close()
    result = []
    for r in rows:
        d = dict(r)
        if d.get('created_at'): d['created_at'] = d['created_at'].isoformat()
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


# ══════════════════════════════════════════════════════════════════════════════
# ADMIN — PATIENTS
# ══════════════════════════════════════════════════════════════════════════════

def get_patients_with_staff(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM patients ORDER BY created_at DESC")
    patients = [dict(r) for r in cur.fetchall()]
    for p in patients:
        if p.get('created_at'): p['created_at'] = p['created_at'].isoformat()
        cur.execute("""SELECT u.id, u.full_name, u.post FROM users u
            JOIN patient_staff ps ON u.id = ps.staff_id WHERE ps.patient_id = %s""", (p['id'],))
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
        cur.execute("""INSERT INTO patients (id, name, age, gender, diagnosis, notes)
            VALUES (%s, %s, %s, %s, %s, %s)""",
            (pid, data['name'], data.get('age'), data.get('gender'),
             data['diagnosis'], data.get('notes', '')))
        conn.commit()
        cur.execute("SELECT * FROM patients WHERE id = %s", (pid,))
        patient = dict(cur.fetchone())
        if patient.get('created_at'): patient['created_at'] = patient['created_at'].isoformat()
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
        fields, values = [], []
        for col in ['name', 'age', 'gender', 'diagnosis', 'notes', 'device_id']:
            if col in data:
                fields.append(f"{col} = %s"); values.append(data[col])
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
            cur.execute("INSERT INTO patient_staff (patient_id, staff_id) VALUES (%s, %s)", (patient_id, sid))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"message": "Staff assigned."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ADMIN — DEVICES
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/admin/devices', methods=['GET'])
def list_devices():
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM devices ORDER BY created_at DESC")
    rows = [dict(r) for r in cur.fetchall()]
    for r in rows:
        if r.get('created_at'): r['created_at'] = r['created_at'].isoformat()
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
        cur.execute("UPDATE patients SET device_id = NULL WHERE device_id = %s", (device_id,))
        cur.execute("UPDATE devices  SET patient_id = %s WHERE device_id = %s", (patient_id, device_id))
        cur.execute("UPDATE patients SET device_id  = %s WHERE id = %s",        (device_id, patient_id))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"message": "Device assigned."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# PROFILE
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/profile/change_password', methods=['POST'])
def change_password():
    try:
        data       = request.get_json()
        user_id    = data.get('user_id')
        current_pw = data.get('current_password', '')
        new_pw     = data.get('new_password', '')
        if not all([user_id, current_pw, new_pw]):
            return jsonify({"error": "All fields are required."}), 400
        if len(new_pw) < 6:
            return jsonify({"error": "New password must be at least 6 characters."}), 400
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT password FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            cur.close(); conn.close()
            return jsonify({"error": "User not found."}), 404
        if row['password'] != hash_pw(current_pw):
            cur.close(); conn.close()
            return jsonify({"error": "Current password is incorrect."}), 401
        cur.execute("UPDATE users SET password = %s WHERE id = %s", (hash_pw(new_pw), user_id))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"message": "Password updated successfully."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/profile/change_photo', methods=['POST'])
def change_photo():
    try:
        data      = request.get_json()
        user_id   = data.get('user_id')
        photo_b64 = data.get('photo_b64')
        if not user_id or not photo_b64:
            return jsonify({"error": "user_id and photo_b64 are required."}), 400
        photo_bytes = base64.b64decode(photo_b64)
        conn = get_db(); cur = conn.cursor()
        cur.execute("UPDATE users SET photo = %s WHERE id = %s",
                    (psycopg2.Binary(photo_bytes), user_id))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"message": "Photo updated successfully."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# VITALS
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/data', methods=['POST'])
def receive_data():
    """
    Accept vitals from any module (hub, temp, belt).
    If temperature arrives as N/A (hub hardware limitation), back-fill
    from the most recent non-null temperature already in the database
    so the dashboard always has a temperature value on hub rows.
    """
    try:
        data = request.get_json(force=True, silent=True) or {}

        def to_float(val):
            if val is None: return None
            try:
                f = float(val)
                return f if f >= 0 else None
            except (ValueError, TypeError):
                return None   # handles "N/A", "", etc.

        temperature      = to_float(data.get('temperature'))
        blood_oxygen     = to_float(data.get('blood_oxygen'))
        heart_rate       = to_float(data.get('heart_rate'))
        respiration_rate = to_float(data.get('respiration_rate'))
        blood_pressure   = data.get('blood_pressure')
        device_id        = str(data.get('device_id', 'UNKNOWN')).strip()

        if not device_id:
            device_id = 'UNKNOWN'

        conn = get_db(); cur = conn.cursor()

        # ── Back-fill temperature from latest reading if hub sent N/A ─────────
        if temperature is None:
            cur.execute(
                "SELECT temperature FROM vitals "
                "WHERE temperature IS NOT NULL "
                "ORDER BY timestamp DESC LIMIT 1"
            )
            row = cur.fetchone()
            if row:
                temperature = row['temperature']

        cur.execute("""INSERT INTO vitals
            (temperature, blood_oxygen, heart_rate, respiration_rate, blood_pressure, device_id)
            VALUES (%s, %s, %s, %s, %s, %s)""",
            (temperature, blood_oxygen, heart_rate, respiration_rate, blood_pressure, device_id))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"message": "Data received", "device_id": device_id}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/vitals', methods=['GET'])
def get_vitals():
    """Return vitals as CSV. Optional ?device_id=XXX filter."""
    try:
        device_filter = request.args.get('device_id')
        conn = get_db(); cur = conn.cursor()
        if device_filter:
            cur.execute("""SELECT timestamp AS "Timestamp",
                temperature AS "Temperature", blood_oxygen AS "Blood Oxygen",
                heart_rate AS "Heart Rate", respiration_rate AS "Respiration Rate",
                blood_pressure AS "Blood Pressure", device_id AS "Device ID"
                FROM vitals WHERE device_id = %s ORDER BY timestamp""", (device_filter,))
        else:
            cur.execute("""SELECT timestamp AS "Timestamp",
                temperature AS "Temperature", blood_oxygen AS "Blood Oxygen",
                heart_rate AS "Heart Rate", respiration_rate AS "Respiration Rate",
                blood_pressure AS "Blood Pressure", device_id AS "Device ID"
                FROM vitals ORDER BY timestamp""")
        rows = cur.fetchall(); cur.close(); conn.close()
        if not rows:
            return jsonify({"error": "No data available"}), 404
        output = io.StringIO()
        writer = csv_mod.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        for row in rows:
            d = dict(row)
            if hasattr(d.get('Timestamp'), 'isoformat'): d['Timestamp'] = d['Timestamp'].isoformat()
            writer.writerow(d)
        return Response(output.getvalue(), mimetype='text/csv')
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/latest_vitals', methods=['GET'])
def latest_vitals():
    """Latest temperature and respiration across all modules for a device_id."""
    try:
        device_id = request.args.get('device_id')
        conn = get_db(); cur = conn.cursor()
        q = "SELECT temperature FROM vitals WHERE temperature IS NOT NULL"
        q += " AND device_id = %s" if device_id else ""
        q += " ORDER BY timestamp DESC LIMIT 1"
        cur.execute(q, (device_id,) if device_id else ())
        t_row = cur.fetchone()

        q2 = "SELECT respiration_rate FROM vitals WHERE respiration_rate IS NOT NULL"
        q2 += " AND device_id = %s" if device_id else ""
        q2 += " ORDER BY timestamp DESC LIMIT 1"
        cur.execute(q2, (device_id,) if device_id else ())
        r_row = cur.fetchone()
        cur.close(); conn.close()

        return jsonify({
            "temperature": round(t_row['temperature'], 1) if t_row else None,
            "respiration": int(r_row['respiration_rate']) if r_row else None,
            "status": "success"
        })
    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ALERTS
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/alerts', methods=['GET'])
def get_alerts():
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 100")
        rows = cur.fetchall(); cur.close(); conn.close()
        result = []
        for row in rows:
            d = dict(row)
            if d.get('timestamp'): d['timestamp'] = d['timestamp'].isoformat()
            result.append(d)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/alerts', methods=['POST'])
def create_alert():
    try:
        data    = request.get_json()
        message = data.get('message', '').strip()
        if not message:
            return jsonify({"error": "message required"}), 400
        conn = get_db(); cur = conn.cursor()
        cur.execute("INSERT INTO alerts (message) VALUES (%s)", (message,))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"message": "Alert saved"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/alerts/<int:alert_id>/dismiss', methods=['POST'])
def dismiss_alert(alert_id):
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("UPDATE alerts SET dismissed = TRUE WHERE id = %s", (alert_id,))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"message": "Alert dismissed"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/alerts/clear', methods=['POST'])
def clear_alerts():
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("DELETE FROM alerts")
        conn.commit(); cur.close(); conn.close()
        return jsonify({"message": "All alerts cleared"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# CASE NOTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/case_notes', methods=['GET'])
def get_case_notes():
    try:
        patient_id = request.args.get('patient_id')
        if not patient_id:
            return jsonify({"error": "patient_id required"}), 400
        conn = get_db(); cur = conn.cursor()
        cur.execute("""SELECT id, patient_id, staff_id, staff_name, note,
            severity, vitals_snapshot, created_at
            FROM case_notes WHERE patient_id = %s ORDER BY created_at DESC""", (patient_id,))
        rows = cur.fetchall(); cur.close(); conn.close()
        result = []
        for row in rows:
            d = dict(row)
            if d.get('created_at'): d['created_at'] = d['created_at'].isoformat()
            result.append(d)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/case_notes', methods=['POST'])
def create_case_note():
    try:
        data            = request.get_json()
        patient_id      = data.get('patient_id', '').strip()
        staff_id        = data.get('staff_id', '').strip()
        staff_name      = data.get('staff_name', '').strip()
        note            = data.get('note', '').strip()
        severity        = data.get('severity', 'Routine').strip()
        vitals_snapshot = data.get('vitals_snapshot')
        if not all([patient_id, staff_id, staff_name, note]):
            return jsonify({"error": "patient_id, staff_id, staff_name and note are required"}), 400
        if severity not in ('Routine', 'Urgent', 'Critical'): severity = 'Routine'
        conn = get_db(); cur = conn.cursor()
        cur.execute("""INSERT INTO case_notes
            (patient_id, staff_id, staff_name, note, severity, vitals_snapshot)
            VALUES (%s, %s, %s, %s, %s, %s) RETURNING id, created_at""",
            (patient_id, staff_id, staff_name, note, severity,
             vitals_snapshot if vitals_snapshot else None))
        row = cur.fetchone()
        conn.commit(); cur.close(); conn.close()
        return jsonify({"message": "Case note saved.", "id": row['id'],
                        "created_at": row['created_at'].isoformat()}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/case_notes/<int:note_id>', methods=['DELETE'])
def delete_case_note(note_id):
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("DELETE FROM case_notes WHERE id = %s", (note_id,))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"message": "Case note deleted."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# CALIBRATION
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/calibration', methods=['GET'])
def get_calibration():
    """Return calibration gain/offset for all parameters of a device."""
    try:
        device_id = request.args.get('device_id', '').strip()
        if not device_id:
            return jsonify({"error": "device_id required"}), 400
        conn = get_db(); cur = conn.cursor()
        cur.execute(
            "SELECT parameter, gain, offset FROM calibration WHERE device_id = %s",
            (device_id,))
        rows = cur.fetchall(); cur.close(); conn.close()
        result = {}
        for row in rows:
            result[row['parameter']] = {"gain": row['gain'], "offset": row['offset']}
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/calibration', methods=['POST'])
def save_calibration():
    """Save calibration values for one or more parameters of a device."""
    try:
        data         = request.get_json()
        device_id    = data.get('device_id', '').strip()
        calibrations = data.get('calibrations', {})
        if not device_id or not calibrations:
            return jsonify({"error": "device_id and calibrations required"}), 400
        conn = get_db(); cur = conn.cursor()
        for param, vals in calibrations.items():
            gain   = float(vals.get('gain',   1.0))
            offset = float(vals.get('offset', 0.0))
            cur.execute("""
                INSERT INTO calibration (device_id, parameter, gain, offset)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (device_id, parameter)
                DO UPDATE SET gain = %s, offset = %s, updated_at = NOW()
            """, (device_id, param, gain, offset, gain, offset))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"message": "Calibration saved."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
