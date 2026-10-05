import argparse
import json
import random
from datetime import datetime, timedelta, timezone


USERNAMES = ["amir", "readonly", "service-account", "jdupont", "mleroy"]

BRUTE_FORCE_IP = "203.0.113.42"
CREDENTIAL_STUFFING_IP = "198.51.100.17"


def make_event(timestamp, event_type, source_ip, username=None, **extra):
    record = {
        "timestamp": timestamp.isoformat(),
        "event_type": event_type,
        "source_ip": source_ip,
        "user_agent": "sample-generator/1.0",
        "request_id": f"req-{random.randint(100000, 999999)}",  # nosec B311
    }
    if username is not None:
        record["username"] = username
    record.update(extra)
    return record


def generate_normal_traffic(start_time, n_events, rng):
    events = []
    current_time = start_time
    for _ in range(n_events):
        current_time += timedelta(seconds=rng.uniform(5, 120))
        username = rng.choice(USERNAMES)
        source_ip = f"10.0.{rng.randint(0, 5)}.{rng.randint(2, 254)}"

        if rng.random() < 0.05:
            events.append(make_event(current_time, "auth_failure", source_ip, username, reason="invalid_credentials"))
            continue

        events.append(make_event(current_time, "auth_success", source_ip, username))
        current_time += timedelta(seconds=rng.uniform(1, 5))
        events.append(make_event(current_time, "resource_access", source_ip, username, resource="/api/resource"))

    return events, current_time


def generate_brute_force_attack(start_time, target_username, attacker_ip, n_attempts, rng):
    events = []
    current_time = start_time
    for _ in range(n_attempts):
        current_time += timedelta(seconds=rng.uniform(1, 8))
        events.append(
            make_event(current_time, "auth_failure", attacker_ip, target_username, reason="invalid_credentials")
        )
    return events, current_time


def generate_credential_stuffing_attack(start_time, attacker_ip, usernames, rng):
    events = []
    current_time = start_time
    for username in usernames:
        current_time += timedelta(seconds=rng.uniform(2, 15))
        events.append(make_event(current_time, "auth_success", attacker_ip, username))
    return events, current_time


def build_dataset(n_normal_events=400, seed=42, start_time=None):
    rng = random.Random(seed)  # nosec B311
    if start_time is None:
        start_time = datetime.now(timezone.utc) - timedelta(hours=6)

    all_events = []

    normal_events, current_time = generate_normal_traffic(start_time, n_normal_events, rng)
    all_events.extend(normal_events)

    brute_force_events, current_time = generate_brute_force_attack(
        current_time + timedelta(minutes=5), "amir", BRUTE_FORCE_IP, n_attempts=12, rng=rng
    )
    all_events.extend(brute_force_events)

    stuffing_events, current_time = generate_credential_stuffing_attack(
        current_time + timedelta(minutes=10), CREDENTIAL_STUFFING_IP,
        ["amir", "readonly", "service-account", "jdupont"], rng=rng
    )
    all_events.extend(stuffing_events)

    more_normal_events, _ = generate_normal_traffic(current_time + timedelta(minutes=15), n_normal_events // 2, rng)
    all_events.extend(more_normal_events)

    all_events.sort(key=lambda e: e["timestamp"])
    return all_events


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="data/sample_logs.jsonl")
    parser.add_argument("--n-normal-events", type=int, default=400)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    all_events = build_dataset(args.n_normal_events, args.seed)

    with open(args.output, "w", encoding="utf-8") as f:
        for event in all_events:
            f.write(json.dumps(event) + "\n")

    print(f"{len(all_events)} evenements generes dans {args.output}")
    print(f"Attaques injectees : brute force sur 'amir' depuis {BRUTE_FORCE_IP}, "
          f"credential stuffing depuis {CREDENTIAL_STUFFING_IP}")


if __name__ == "__main__":
    main()
