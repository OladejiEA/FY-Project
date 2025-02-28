from flask import Flask, request, jsonify
import gspread
import os
from oauth2client.service_account import ServiceAccountCredentials
from datetime import datetime

app = Flask(__name__)

# Google Sheets setup
SCOPE = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
CREDS_FILE = "credentials.json"
SPREADSHEET_NAME = "PatientVitals"

# Initialize Google Sheets client
creds = ServiceAccountCredentials.from_json_keyfile_name(CREDS_FILE, SCOPE)
client = gspread.authorize(creds)
sheet = client.open(SPREADSHEET_NAME).sheet1

# Initialize sheet with header if empty
def init_sheet():
    if not sheet.row_values(1):
        header = ["Timestamp", "Temperature", "Blood Oxygen", "Heart Rate", "Respiration Rate", "Blood Pressure"]
        sheet.append_row(header)
        print("Initialized Google Sheet with header")

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

        # Append data to Google Sheets
        row = [timestamp, temperature, blood_oxygen, heart_rate, respiration_rate, blood_pressure]
        sheet.append_row(row)
        print(f"Appended data: {row}")

        return jsonify({"message": "Data received successfully"}), 200
    except Exception as e:
        print(f"Error in receive_data: {e}")
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    init_sheet()
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
