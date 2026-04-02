from flask import Flask, request, jsonify, send_file, Response
import csv
from datetime import datetime
import os
import json
import hashlib
import uuid
import io

app = Flask(__name__)

# ─── File paths ──────────────────────────────────────────────────────────────────
DATA_FILE     = 'vitals.csv'
USERS_FILE    = 'users.json'
PATIENTS_FILE = 'patients.json'
DEVICES_FILE  = 'devices.json'
UPLOAD_FOLDER = 'uploads'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ─── Init CSV ────────────────────────────────────────────────────────────────────
if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, mode='w', newline='') as f:
        csv.writer(f).writerow([
            'Timestamp', 'Temperature', 'Blood Oxygen',
            'Heart Rate', 'Respiration Rate', 'Blood Pressure', 'Device ID'
        ])

# ─── Helpers ─────────────────────────────────────────────────────────────────────
def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def load_json(path, default):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return default

def save_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

# ─── Seed default admin ──────────────────────────────────────────────────────────
def seed_admin():
    users = load_json(USERS_FILE, {})
    if not any(u.get('role') == 'admin' for u in users.values()):
        uid = str(uuid.uuid4())
        users[uid] = {
            "id": uid,
            "full_name": "System Admin",
            "email": "admin@vitatrack.com",
            "password": hash_password("admin123"),
            "role": "admin",
            "post": "Administrator",
            "photo": None,
            "created_at": datetime.now().isoformat(),
            "approved": True
        }
        save_json(USERS_FILE, users)

seed_admin()

# ══════════════════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ══════════════════════════════════════════════════════════════════════════════════

@app.route('/auth/signup', methods=['POST'])
def signup():
    try:
        data      = request.get_json()
        full_name = data.get('full_name', '').strip()
        email     = data.get('email', '').strip().lower()
        password  = data.get('password', '')
        post      = data.get('post', '')
        photo_b64 = data.get('photo_b64', None)

        if not all([full_name, email, password, post]):
            return jsonify({"error": "All fields are required."}), 400

        users = load_json(USERS_FILE, {})
        if any(u['email'] == email for u in users.values()):
            return jsonify({"error": "Email already registered."}), 409

        uid = str(uuid.uuid4())
        photo_path = None
        if photo_b64:
            import base64
            photo_path = os.path.join(UPLOAD_FOLDER, f"{uid}.jpg")
            with open(photo_path, 'wb') as pf:
                pf.write(base64.b64decode(photo_b64))

        users[uid] = {
            "id":         uid,
            "full_name":  full_name,
            "email":      email,
            "password":   hash_password(password),
            "role":       "staff",
            "post":       post,
            "photo":      photo_path,
            "created_at": datetime.now().isoformat(),
            "approved":   False
        }
        save_json(USERS_FILE, users)
        return jsonify({"message": "Account created. Awaiting admin approval.", "id": uid}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/auth/login', methods=['POST'])
def login():
    try:
        data     = request.get_json()
        email    = data.get('email', '').strip().lower()
        password = data.get('password', '')

        users = load_json(USERS_FILE, {})
        user  = next((u for u in users.values() if u['email'] == email), None)

        if not user or user['password'] != hash_password(password):
            return jsonify({"error": "Invalid email or password."}), 401
        if not user.get('approved', False):
            return jsonify({"error": "Account pending admin approval."}), 403

        safe = {k: v for k, v in user.items() if k != 'password'}
        return jsonify({"message": "Login successful.", "user": safe}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/auth/photo/<user_id>', methods=['GET'])
def get_photo(user_id):
    users = load_json(USERS_FILE, {})
    user  = users.get(user_id)
    if not user or not user.get('photo') or not os.path.exists(user['photo']):
        return jsonify({"error": "Photo not found"}), 404
    return send_file(user['photo'], mimetype='image/jpeg')


# ══════════════════════════════════════════════════════════════════════════════════
# ADMIN — USER MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════════

@app.route('/admin/users', methods=['GET'])
def list_users():
    users = load_json(USERS_FILE, {})
    safe  = [{k: v for k, v in u.items() if k != 'password'} for u in users.values()]
    return jsonify(safe), 200


@app.route('/admin/approve/<user_id>', methods=['POST'])
def approve_user(user_id):
    users = load_json(USERS_FILE, {})
    if user_id not in users:
        return jsonify({"error": "User not found"}), 404
    users[user_id]['approved'] = True
    save_json(USERS_FILE, users)
    return jsonify({"message": "User approved."}), 200


@app.route('/admin/reject/<user_id>', methods=['DELETE'])
def reject_user(user_id):
    users = load_json(USERS_FILE, {})
    if user_id not in users:
        return jsonify({"error": "User not found"}), 404
    del users[user_id]
    save_json(USERS_FILE, users)
    return jsonify({"message": "User removed."}), 200


# ══════════════════════════════════════════════════════════════════════════════════
# ADMIN — PATIENTS
# ══════════════════════════════════════════════════════════════════════════════════

@app.route('/admin/patients', methods=['GET'])
def list_patients():
    return jsonify(load_json(PATIENTS_FILE, [])), 200


@app.route('/admin/patients', methods=['POST'])
def create_patient():
    try:
        data     = request.get_json()
        required = ['name', 'age', 'gender', 'diagnosis']
        if not all(data.get(f) for f in required):
            return jsonify({"error": "name, age, gender, diagnosis required."}), 400

        patients = load_json(PATIENTS_FILE, [])
        patient  = {
            "id":          str(uuid.uuid4()),
            "name":        data['name'],
            "age":         data['age'],
            "gender":      data['gender'],
            "diagnosis":   data['diagnosis'],
            "notes":       data.get('notes', ''),
            "device_id":   None,
            "assigned_to": [],
            "created_at":  datetime.now().isoformat()
        }
        patients.append(patient)
        save_json(PATIENTS_FILE, patients)
        return jsonify({"message": "Patient created.", "patient": patient}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/admin/patients/<patient_id>', methods=['PUT'])
def update_patient(patient_id):
    try:
        data     = request.get_json()
        patients = load_json(PATIENTS_FILE, [])
        patient  = next((p for p in patients if p['id'] == patient_id), None)
        if not patient:
            return jsonify({"error": "Patient not found"}), 404
        for key in ['name', 'age', 'gender', 'diagnosis', 'notes', 'device_id', 'assigned_to']:
            if key in data:
                patient[key] = data[key]
        save_json(PATIENTS_FILE, patients)
        return jsonify({"message": "Patient updated.", "patient": patient}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/admin/patients/<patient_id>', methods=['DELETE'])
def delete_patient(patient_id):
    patients = load_json(PATIENTS_FILE, [])
    patients = [p for p in patients if p['id'] != patient_id]
    save_json(PATIENTS_FILE, patients)
    return jsonify({"message": "Patient deleted."}), 200


# ══════════════════════════════════════════════════════════════════════════════════
# ADMIN — DEVICES
# ══════════════════════════════════════════════════════════════════════════════════

@app.route('/admin/devices', methods=['GET'])
def list_devices():
    return jsonify(load_json(DEVICES_FILE, [])), 200


@app.route('/admin/devices', methods=['POST'])
def create_device():
    try:
        data   = request.get_json()
        dev_id = data.get('device_id', '').strip()
        label  = data.get('label', '')
        if not dev_id:
            return jsonify({"error": "device_id is required."}), 400

        devices = load_json(DEVICES_FILE, [])
        if any(d['device_id'] == dev_id for d in devices):
            return jsonify({"error": "Device ID already exists."}), 409

        device = {
            "device_id":  dev_id,
            "label":      label,
            "patient_id": None,
            "active":     True,
            "created_at": datetime.now().isoformat()
        }
        devices.append(device)
        save_json(DEVICES_FILE, devices)
        return jsonify({"message": "Device registered.", "device": device}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/admin/devices/assign', methods=['POST'])
def assign_device():
    try:
        data       = request.get_json()
        device_id  = data.get('device_id')
        patient_id = data.get('patient_id')

        devices  = load_json(DEVICES_FILE, [])
        patients = load_json(PATIENTS_FILE, [])

        device  = next((d for d in devices  if d['device_id'] == device_id), None)
        patient = next((p for p in patients if p['id']        == patient_id), None)

        if not device:
            return jsonify({"error": "Device not found"}), 404
        if not patient:
            return jsonify({"error": "Patient not found"}), 404

        for p in patients:
            if p.get('device_id') == device_id:
                p['device_id'] = None

        device['patient_id'] = patient_id
        patient['device_id'] = device_id

        save_json(DEVICES_FILE, devices)
        save_json(PATIENTS_FILE, patients)
        return jsonify({"message": f"Device {device_id} assigned to {patient['name']}."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/admin/assign_staff', methods=['POST'])
def assign_staff():
    try:
        data       = request.get_json()
        patient_id = data.get('patient_id')
        staff_ids  = data.get('staff_ids', [])

        patients = load_json(PATIENTS_FILE, [])
        patient  = next((p for p in patients if p['id'] == patient_id), None)
        if not patient:
            return jsonify({"error": "Patient not found"}), 404

        patient['assigned_to'] = staff_ids
        save_json(PATIENTS_FILE, patients)
        return jsonify({"message": "Staff assigned.", "patient": patient}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════════
# VITALS  (extended with device_id)
# ══════════════════════════════════════════════════════════════════════════════════

@app.route('/data', methods=['POST'])
def receive_data():
    try:
        data             = request.get_json()
        temperature      = data.get('temperature')
        blood_oxygen     = data.get('blood_oxygen')
        heart_rate       = data.get('heart_rate')
        respiration_rate = data.get('respiration_rate')
        blood_pressure   = data.get('blood_pressure')
        device_id        = data.get('device_id', 'UNKNOWN')
        timestamp        = datetime.now().isoformat()

        with open(DATA_FILE, mode='a', newline='') as f:
            csv.writer(f).writerow([
                timestamp, temperature, blood_oxygen,
                heart_rate, respiration_rate, blood_pressure, device_id
            ])
        return jsonify({"message": "Data received successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/vitals', methods=['GET'])
def get_vitals():
    try:
        if not os.path.exists(DATA_FILE):
            return jsonify({"error": "No data"}), 404
        device_filter = request.args.get('device_id')
        if device_filter:
            rows = []
            with open(DATA_FILE) as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get('Device ID') == device_filter:
                        rows.append(row)
            if not rows:
                return jsonify({"error": "No data for this device"}), 404
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
            return Response(output.getvalue(), mimetype='text/csv')
        return send_file(DATA_FILE, mimetype='text/csv')
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
