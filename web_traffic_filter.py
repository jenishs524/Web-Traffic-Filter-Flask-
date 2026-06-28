#!/usr/bin/env python3
from flask import Flask, request, jsonify, render_template_string
import re
import time
from collections import defaultdict

app = Flask(__name__)

# --- Configuration ---
REQUEST_LIMIT = 50          # max requests per minute per IP
TIME_WINDOW = 60            # seconds
request_counts = defaultdict(list)

# --- Suspicious patterns ---
SQL_PATTERNS = [
    r'(\%27)|(\')|(\-\-)|(\%23)|(#)',
    r'((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))',
    r'(union|select|insert|update|delete|drop|alter|create)\s+.*\s+(from|into|set|where)',
]

XSS_PATTERNS = [
    r'<script[^>]*>.*?</script>',
    r'<.*?on\w+=".*?".*?>',
    r'javascript:.*',
]

PATH_TRAVERSAL = [
    r'\.\./\.\./',
    r'\.\.\\\.\.\\',
    r'/etc/passwd',
    r'/etc/shadow',
]

CMD_INJECTION = [
    r';\s*(ls|dir|cat|type|echo|net|whoami|id|pwd|cd)',
    r'\|\s*(ls|dir|cat|type|echo|net|whoami|id|pwd|cd)',
    r'&\s*(ls|dir|cat|type|echo|net|whoami|id|pwd|cd)',
]

ALL_PATTERNS = SQL_PATTERNS + XSS_PATTERNS + PATH_TRAVERSAL + CMD_INJECTION

def is_suspicious(value):
    """Check a string against all suspicious patterns."""
    if not value:
        return False
    for pattern in ALL_PATTERNS:
        if re.search(pattern, str(value), re.IGNORECASE):
            return True
    return False

@app.before_request
def filter_request():
    # --- Rate limiting ---
    client_ip = request.remote_addr
    current_time = time.time()
    request_counts[client_ip] = [t for t in request_counts[client_ip] if current_time - t < TIME_WINDOW]
    request_counts[client_ip].append(current_time)
    if len(request_counts[client_ip]) > REQUEST_LIMIT:
        return jsonify({"error": "Rate limit exceeded"}), 429

    # --- Content filtering ---
    # Check URL
    if is_suspicious(request.url):
        return jsonify({"error": "Suspicious content blocked (URL)"}), 403

    # Check query parameters
    for key, value in request.args.items():
        if is_suspicious(value):
            return jsonify({"error": f"Suspicious content blocked (param: {key})"}), 403

    # Check form data (POST)
    for key, value in request.form.items():
        if is_suspicious(value):
            return jsonify({"error": f"Suspicious content blocked (form: {key})"}), 403

    # Check JSON body
    if request.is_json and request.json:
        for key, value in request.json.items():
            if is_suspicious(str(value)):
                return jsonify({"error": f"Suspicious content blocked (JSON: {key})"}), 403

@app.route('/')
def home():
    return '''
    <h1>🛡️ Web Traffic Filter</h1>
    <p>This application blocks suspicious requests (SQLi, XSS, path traversal, command injection).</p>
    <p>Try sending these test payloads:</p>
    <ul>
        <li><code>/?id=1' OR '1'='1</code> → blocked</li>
        <li><code>/?q=&lt;script&gt;alert(1)&lt;/script&gt;</code> → blocked</li>
        <li><code>/?file=../../etc/passwd</code> → blocked</li>
    </ul>
    <p>Normal requests like <code>/?id=123</code> are allowed.</p>
    '''

@app.route('/status')
def status():
    return jsonify({
        "active_ips": {ip: len(ts) for ip, ts in request_counts.items()}
    })

if __name__ == '__main__':
    print("=" * 60)
    print("  WEB TRAFFIC FILTER")
    print("=" * 60)
    print("[*] Starting Flask server on http://0.0.0.0:5000")
    print("[*] Press Ctrl+C to stop")
    app.run(host='0.0.0.0', port=5000, debug=False)
