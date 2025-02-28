from flask import Flask, request, jsonify
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime
import os

app = Flask(__name__)

# Firebase setup
CREDS_FILE = "credentials.json"  # Path to Firebase service account key
cred = credentials.Certificate(CREDS_FILE)
firebase_admin.initialize_app(cred)
db = firestore.client()
vitals_ref = db.collection('vitals')  # Firestore collection name

# Receive data from ESP32 or Streamlit BP input
@app.route('/data', methods=['POST'])
def receive_data():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        # Extract fields with default None if missing
        temperature = data.get('temperature')
        blood_oxygen = data.get('blood_oxygen')
        heart_rate = data.get('heart_rate')
        respiration_rate = data.get('respiration_rate')
        blood_pressure = data.get('blood_pressure')
        timestamp = datetime.now().isoformat()

        # Create a document with data
        vital_data = {
            "timestamp": timestamp,
            "temperature": temperature if temperature is not None else None,
            "blood_oxygen": blood_oxygen if blood_oxygen != "No data measured" else None,
            "heart_rate": heart_rate if heart_rate != "No data measured" else None,
            "respiration_rate": respiration_rate if respiration_rate != "No data measured" else None,
            "blood_pressure": blood_pressure
        }

        # Add to Firestore (auto-generates document ID)
        vitals_ref.add(vital_data)
        print(f"Appended data: {vital_data}")

        return jsonify({"message": "Data received successfully"}), 200
    except Exception as e:
        print(f"Error in receive_data: {e}")
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
