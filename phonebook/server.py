import json
import os
from flask import Flask, send_from_directory, request, jsonify

app = Flask(__name__, static_folder='.')
DATA_FILE = 'data/db.json'

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/api/data', methods=['GET'])
def get_data():
    if not os.path.exists('data'):
        os.makedirs('data')
    if not os.path.exists(DATA_FILE):
        return jsonify({"users": [{"username": "admin", "pass": "admin123", "role": "admin"}], "contacts": []})
    with open(DATA_FILE, 'r', encoding='utf-8') as f:
        return jsonify(json.load(f))

@app.route('/api/contacts', methods=['POST'])
def update_contacts():
    contacts = request.json
    data = {}
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    data['contacts'] = contacts
    if 'users' not in data:
        data['users'] = [{"username": "admin", "pass": "admin123", "role": "admin"}]
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return jsonify({"status": "ok"})

@app.route('/api/users', methods=['POST'])
def update_users():
    users = request.json
    data = {}
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    data['users'] = users
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
