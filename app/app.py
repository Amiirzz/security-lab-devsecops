import json
import logging
import logging.handlers
import os
import sys
import time
import uuid
from datetime import datetime, timezone

from flask import Flask, g, jsonify, request
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

TRUSTED_PROXY_HOPS = int(os.environ.get("TRUSTED_PROXY_HOPS", "0"))
if TRUSTED_PROXY_HOPS > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUSTED_PROXY_HOPS, x_proto=TRUSTED_PROXY_HOPS)

logger = logging.getLogger("app")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(_handler)

LOG_FILE = os.environ.get("LOG_FILE")
if LOG_FILE:
    _file_handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=10_000_000, backupCount=3)
    _file_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(_file_handler)

USERS = {
    "amir": generate_password_hash("Str0ngP@ssword!"),
    "readonly": generate_password_hash("ReadOnly123!"),
    "jdupont": generate_password_hash("Jdupont#2026"),
    "mleroy": generate_password_hash("Mleroy#2026"),
}

_DUMMY_HASH = generate_password_hash(str(uuid.uuid4()))

ACTIVE_SESSIONS = {}

_WARNING_EVENTS = {"auth_failure", "access_denied"}


def log_event(event_type, **fields):
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": "WARNING" if event_type in _WARNING_EVENTS else "INFO",
        "event_type": event_type,
        "source_ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", ""),
        "request_id": g.get("request_id", ""),
    }
    record.update(fields)
    logger.info(json.dumps(record))


@app.before_request
def assign_request_id():
    g.request_id = str(uuid.uuid4())


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/login", methods=["POST"])
def login():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", ""))
    password = str(payload.get("password", ""))

    stored_hash = USERS.get(username)
    password_ok = check_password_hash(stored_hash or _DUMMY_HASH, password)
    if stored_hash is None or not password_ok:
        log_event("auth_failure", username=username, reason="invalid_credentials")
        return jsonify({"error": "invalid credentials"}), 401

    token = str(uuid.uuid4())
    ACTIVE_SESSIONS[token] = {"username": username, "issued_at": time.time()}
    log_event("auth_success", username=username)
    return jsonify({"token": token})


def _authenticate():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header.removeprefix("Bearer ")
    return ACTIVE_SESSIONS.get(token)


@app.route("/api/resource", methods=["GET"])
def get_resource():
    session = _authenticate()
    if session is None:
        log_event("access_denied", resource="/api/resource")
        return jsonify({"error": "unauthorized"}), 401

    log_event("resource_access", resource="/api/resource", username=session["username"])
    return jsonify({"data": "resource-payload", "owner": session["username"]})


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8080")))
