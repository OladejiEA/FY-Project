import os
from flask import Flask, request, jsonify, send_file
import csv
from datetime import datetime

app = Flask(__name__)

# File to store the data
DATA_FILE = 'vitals.csv'

# Initialize CSV if it doesn’t exist
if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Timestamp', 'Temperature', 'Blood Oxygen', 'Heart Rate', 'Respiration Rate', 'Blood Pressure'])

# Receive data from ESP32 or Streamlit BP input
@app.route('/data', methods=['POST'])
def receive_data():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        temperature = data.get('temperature')
        blood_oxygen = data.get('blood_oxygen')
        heart_rate = data.get('heart_rate')
        respiration_rate = data.get('respiration_rate')
        blood_pressure = data.get('blood_pressure')
        timestamp = datetime.now().isoformat()

        # Append to CSV
        with open(DATA_FILE, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([timestamp, temperature, blood_oxygen, heart_rate, respiration_rate, blood_pressure])
        print(f"Appended data: {timestamp}, {temperature}, {blood_oxygen}, {heart_rate}, {respiration_rate}, {blood_pressure}")

        return jsonify({"message": "Data received successfully"}), 200
    except Exception as e:
        print(f"Error in receive_data: {e}")
        return jsonify({"error": str(e)}), 400

# Serve the vitals data as CSV
@app.route('/vitals', methods=['GET'])
def get_vitals():
    try:
        if os.path.exists(DATA_FILE):
            return send_file(DATA_FILE, mimetype='text/csv')
        return jsonify({"error": "No data available"}), 404
    except Exception as e:
        print(f"Error in get_vitals: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
