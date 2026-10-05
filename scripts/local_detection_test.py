import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta


def normalize_event(raw):
    event = dict(raw)
    event["timestamp"] = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    return event


def load_events(path):
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "event_type" in raw:
                events.append(normalize_event(raw))
    return events


def detect_brute_force(events, window=timedelta(minutes=5), threshold=5):
    failures_by_ip = defaultdict(list)
    for event in events:
        if event["event_type"] == "auth_failure":
            failures_by_ip[event["source_ip"]].append(event)

    alerts = []
    for source_ip, failures in failures_by_ip.items():
        failures.sort(key=lambda e: e["timestamp"])
        window_start = 0
        for i in range(len(failures)):
            while failures[i]["timestamp"] - failures[window_start]["timestamp"] > window:
                window_start += 1
            count_in_window = i - window_start + 1
            if count_in_window >= threshold:
                usernames = sorted({e.get("username", "") for e in failures[window_start:i + 1]})
                alerts.append({
                    "rule": "brute_force_login",
                    "source_ip": source_ip,
                    "failed_attempts": count_in_window,
                    "usernames_targeted": usernames,
                    "window_end": failures[i]["timestamp"].isoformat(),
                })
                break

    return alerts


def detect_credential_stuffing(events, window=timedelta(minutes=10), threshold=3):
    successes_by_ip = defaultdict(list)
    for event in events:
        if event["event_type"] == "auth_success":
            successes_by_ip[event["source_ip"]].append(event)

    alerts = []
    for source_ip, successes in successes_by_ip.items():
        successes.sort(key=lambda e: e["timestamp"])
        window_start = 0
        for i in range(len(successes)):
            while successes[i]["timestamp"] - successes[window_start]["timestamp"] > window:
                window_start += 1
            usernames_in_window = {e.get("username", "") for e in successes[window_start:i + 1]}
            if len(usernames_in_window) >= threshold:
                alerts.append({
                    "rule": "multiple_accounts_same_ip",
                    "source_ip": source_ip,
                    "distinct_usernames": sorted(usernames_in_window),
                    "window_end": successes[i]["timestamp"].isoformat(),
                })
                break

    return alerts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--logs", default="data/sample_logs.jsonl")
    args = parser.parse_args()

    events = load_events(args.logs)
    print(f"{len(events)} evenements charges depuis {args.logs}")

    brute_force_alerts = detect_brute_force(events)
    stuffing_alerts = detect_credential_stuffing(events)

    print(f"\nAlertes brute force detectees : {len(brute_force_alerts)}")
    for alert in brute_force_alerts:
        print(f"  {alert}")

    print(f"\nAlertes credential stuffing detectees : {len(stuffing_alerts)}")
    for alert in stuffing_alerts:
        print(f"  {alert}")


if __name__ == "__main__":
    main()
