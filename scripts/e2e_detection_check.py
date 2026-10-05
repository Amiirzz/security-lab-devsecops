import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

LOKI_URL = os.environ.get("LOKI_URL", "http://loki:3100")
RULES_DIR = Path(os.environ.get("RULES_DIR", "siem/detection_rules"))
TIMEOUT = int(os.environ.get("CHECK_TIMEOUT", "120"))

EXPECTED = {
    "brute_force_login": {os.environ.get("BRUTEFORCE_IP", "172.28.0.66")},
    "multiple_accounts_same_ip": {os.environ.get("STUFFING_IP", "172.28.0.77")},
}


def query_loki(expr):
    url = f"{LOKI_URL}/loki/api/v1/query?" + urllib.parse.urlencode({"query": expr})
    with urllib.request.urlopen(url, timeout=15) as resp:  # nosec B310
        body = json.loads(resp.read())
    return {series["metric"].get("source_ip") for series in body["data"]["result"]}


def main():
    results = {}
    deadline = time.time() + TIMEOUT
    while True:
        results = {name: query_loki((RULES_DIR / f"{name}.logql").read_text()) for name in EXPECTED}
        if results == EXPECTED or time.time() > deadline:
            break
        time.sleep(5)

    ok = True
    for name, expected in EXPECTED.items():
        found = results[name]
        status = "OK " if found == expected else "ECHEC"
        ok &= found == expected
        print(f"[{status}] {name}: attendu {sorted(expected)}, detecte {sorted(found)}")
        if found - expected:
            print(f"        faux positifs : {sorted(found - expected)}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
