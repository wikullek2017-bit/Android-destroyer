import os
import hmac
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, request, jsonify, abort
import psutil
import subprocess

TOKEN = os.environ.get("TEAHACK_TOKEN", "")
HOST = os.environ.get("TEAHACK_HOST", "127.0.0.1")
PORT = int(os.environ.get("TEAHACK_PORT", "8443"))
CERT = os.environ.get("TEAHACK_CERT", "")
KEY = os.environ.get("TEAHACK_KEY", "")
if len(TOKEN) < 32:
    raise SystemExit("Set TEAHACK_TOKEN to a random secret of at least 32 characters.")
if not CERT or not KEY or not os.path.isfile(CERT) or not os.path.isfile(KEY):
    raise SystemExit("Set TEAHACK_CERT and TEAHACK_KEY to valid TLS certificate/key files.")

app = Flask(__name__)
handler = RotatingFileHandler("teahack-agent.log", maxBytes=1_000_000, backupCount=3)
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

# Fixed allowlist: clients cannot supply arbitrary executable paths or arguments.
ALLOWED_APPS = {
    "notepad": ["notepad.exe"],
    "calculator": ["calc.exe"],
}

@app.before_request
def authenticate():
    if request.path == "/health":
        return
    supplied = request.headers.get("Authorization", "")
    expected = "Bearer " + TOKEN
    if not hmac.compare_digest(supplied, expected):
        app.logger.warning("Rejected unauthenticated request from %s", request.remote_addr)
        abort(401)

@app.get("/health")
def health():
    return jsonify({"service": "TEAHACK Agent", "status": "online"})

@app.get("/api/status")
def status():
    app.logger.info("System status requested by %s", request.remote_addr)
    return jsonify({
        "computer": os.environ.get("COMPUTERNAME", "Windows computer"),
        "platform": __import__("platform").platform(),
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "ram_percent": psutil.virtual_memory().percent,
        "ram_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        "boot_time": psutil.boot_time(),
    })

@app.get("/api/processes")
def processes():
    rows = []
    for p in psutil.process_iter(["pid", "name", "username"]):
        try:
            rows.append(p.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if len(rows) >= 150:
            break
    app.logger.info("Process inventory requested by %s", request.remote_addr)
    return jsonify(rows)

@app.post("/api/launch")
def launch():
    data = request.get_json(silent=True) or {}
    name = data.get("app", "")
    command = ALLOWED_APPS.get(name)
    if command is None:
        return jsonify({"error": "Application is not on the approved allowlist."}), 400
    # No shell, no client-supplied command line, no arbitrary paths.
    subprocess.Popen(command, shell=False)
    app.logger.info("Approved app '%s' launched by %s", name, request.remote_addr)
    return jsonify({"ok": True, "launched": name})

if __name__ == "__main__":
    print(f"TEAHACK Agent listening on https://{HOST}:{PORT}")
    # TLS is mandatory; do not replace with a plaintext listener.
    app.run(host=HOST, port=PORT, ssl_context=(CERT, KEY), threaded=True)
