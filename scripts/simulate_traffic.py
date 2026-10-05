import json
import os
import random
import sys
import time
import urllib.error
import urllib.request

TARGET = os.environ.get("TARGET_URL", "http://proxy:8080")
USER_AGENT = os.environ.get("USER_AGENT", "lab-simulator/1.0")

LEAKED_CREDENTIALS = [
    ("amir", "Str0ngP@ssword!"),
    ("readonly", "ReadOnly123!"),
    ("jdupont", "Jdupont#2026"),
    ("mleroy", "azerty123"),
    ("admin", "admin"),
]

PASSWORD_WORDLIST = [
    "123456", "password", "azerty", "admin", "letmein", "qwerty",
    "Password1", "welcome", "monkey", "dragon", "soleil", "motdepasse",
]


def _request(method, path, payload=None, token=None):
    headers = {"User-Agent": USER_AGENT}
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"{TARGET}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as err:
        return err.code, {}


def login(username, password):
    status, body = _request("POST", "/login", {"username": username, "password": password})
    return body.get("token") if status == 200 else None


def wait_for_target(timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if _request("GET", "/health")[0] == 200:
                return
        except urllib.error.URLError:
            pass
        time.sleep(2)
    sys.exit(f"Cible injoignable : {TARGET}")


def run_normal(rng):
    username = os.environ["SIM_USERNAME"]
    password = os.environ["SIM_PASSWORD"]
    iterations = int(os.environ.get("ITERATIONS", "20"))
    for _ in range(iterations):
        if rng.random() < 0.03:
            login(username, password + "x")
        token = login(username, password)
        if token:
            _request("GET", "/api/resource", token=token)
        time.sleep(rng.uniform(2, 6))


def run_bruteforce(rng):
    target_user = os.environ.get("SIM_TARGET_USER", "amir")
    for password in PASSWORD_WORDLIST:
        login(target_user, password)
        time.sleep(rng.uniform(0.5, 3))


def run_stuffing(rng):
    for username, password in LEAKED_CREDENTIALS:
        token = login(username, password)
        if token:
            _request("GET", "/api/resource", token=token)
        time.sleep(rng.uniform(1, 5))


MODES = {"normal": run_normal, "bruteforce": run_bruteforce, "stuffing": run_stuffing}


def main():
    mode = os.environ.get("MODE", "normal")
    if mode not in MODES:
        sys.exit(f"MODE inconnu : {mode} (attendu : {', '.join(MODES)})")
    rng = random.Random()  # nosec B311
    wait_for_target()
    print(f"[{mode}] debut de la simulation vers {TARGET}", flush=True)
    MODES[mode](rng)
    print(f"[{mode}] termine", flush=True)


if __name__ == "__main__":
    main()
