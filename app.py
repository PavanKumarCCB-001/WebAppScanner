from flask import Flask, render_template, request, redirect, url_for
from scanner import WebSecurityScanner
import json
import os

HISTORY_FILE = 'scan_history.json'

# Load history if exists
if os.path.exists(HISTORY_FILE):
    with open(HISTORY_FILE, 'r') as f:
        scan_history = json.load(f)
else:
    scan_history = {}

def save_history():
    with open(HISTORY_FILE, 'w') as f:
        json.dump(scan_history, f)

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        if not url.startswith('http'):
            error = "URL must start with http:// or https://"
            return render_template('index.html', error=error)
        scanner = WebSecurityScanner(url)
        vulns = scanner.scan()
        scan_id = str(len(scan_history))
        scan_history[scan_id] = {
            'url': url,
            'results': vulns
        }
        save_history()  # Save after adding scan
        return redirect(url_for('report', scan_id=scan_id))
    return render_template('index.html', error=None)

@app.route('/report/<scan_id>')
def report(scan_id):
    data = scan_history.get(scan_id)
    if not data:
        return "Report not found", 404
    return render_template('report.html', data=data, scan_id=scan_id)

app.run(host='0.0.0.0',debug=True)
