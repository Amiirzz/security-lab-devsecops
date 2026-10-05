import json
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent / "scripts"))

from generate_sample_logs import (  # noqa: E402
    BRUTE_FORCE_IP,
    CREDENTIAL_STUFFING_IP,
    build_dataset,
)
from local_detection_test import (  # noqa: E402
    detect_brute_force,
    detect_credential_stuffing,
    load_events,
    normalize_event,
)


def _events():
    return [normalize_event(e) for e in build_dataset(n_normal_events=400, seed=42)]


def test_brute_force_detects_only_attacker():
    alerts = detect_brute_force(_events())
    assert {a["source_ip"] for a in alerts} == {BRUTE_FORCE_IP}


def test_credential_stuffing_detects_only_attacker():
    alerts = detect_credential_stuffing(_events())
    assert {a["source_ip"] for a in alerts} == {CREDENTIAL_STUFFING_IP}


def test_no_alert_on_normal_traffic_only():
    events = [e for e in _events() if e["source_ip"] not in (BRUTE_FORCE_IP, CREDENTIAL_STUFFING_IP)]
    assert detect_brute_force(events) == []
    assert detect_credential_stuffing(events) == []


def test_load_events_skips_non_json_lines(tmp_path):
    lines = [
        json.dumps({"timestamp": f"2026-10-06T10:00:0{i}+00:00", "event_type": "auth_failure",
                    "source_ip": "192.0.2.1", "username": "amir"})
        for i in range(6)
    ] + ["[2026-10-06 10:00:09 +0000] [1] [INFO] Booting worker"]
    path = tmp_path / "events.log"
    path.write_text("\n".join(lines), encoding="utf-8")

    events = load_events(path)
    assert len(events) == 6
    assert detect_brute_force(events)[0]["source_ip"] == "192.0.2.1"
