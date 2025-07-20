# ui_alert_server.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Store list of alerts with timestamps
alerts = []

@app.route('/push_alert', methods=['POST'])
def push_alert():
    data = request.get_json()
    message = data.get('alert', '')
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Avoid duplicate alerts (based on message)
    if not any(alert['message'] == message for alert in alerts):
        alerts.append({'message': message, 'timestamp': timestamp})

    return jsonify({"status": "received"}), 200

@app.route('/get_alerts', methods=['GET'])
def get_alerts():
    return jsonify(alerts)

@app.route('/clear_alerts', methods=['POST'])
def clear_alerts():
    alerts.clear()
    return jsonify({"status": "cleared"}), 200

if __name__ == '__main__':
    app.run(port=5050)
