from flask import Flask, render_template, jsonify
import json
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

@app.route('/')
def index():
    logger.debug("Serving index.html")
    return render_template('index.html')

@app.route('/api/data')
def get_data():
    logger.debug("Fetching data from mqtt_inference_packets.json")
    logs = []
    try:
        with open('mqtt_inference_packets.json', 'r') as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    logs.append(log_entry)
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse JSON line: {e}")
                    continue
        logger.debug(f"Returning {len(logs)} log entries")
        return jsonify(logs[-100:])
    except FileNotFoundError:
        logger.warning("mqtt_inference_packets.json not found, returning empty list")
        return jsonify([])
    except Exception as e:
        logger.error(f"Error reading log file: {e}")
        return jsonify([]), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)