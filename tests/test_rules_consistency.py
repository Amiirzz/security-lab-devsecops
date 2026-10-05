import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT / "app"))
sys.path.append(str(ROOT / "scripts"))

from app import USERS  # noqa: E402
from simulate_traffic import LEAKED_CREDENTIALS  # noqa: E402
from werkzeug.security import check_password_hash  # noqa: E402

RULES_DIR = ROOT / "siem" / "detection_rules"
ALERTS_FILE = ROOT / "observability" / "grafana" / "provisioning" / "alerting" / "detection_rules.yaml"


def _grafana_rules():
    content = yaml.safe_load(ALERTS_FILE.read_text(encoding="utf-8"))
    return {rule["labels"]["detection_rule"]: rule for group in content["groups"] for rule in group["rules"]}


def test_every_rule_file_is_deployed_in_grafana():
    rule_files = {p.stem for p in RULES_DIR.glob("*.logql")}
    assert rule_files == set(_grafana_rules())


def test_grafana_queries_match_rule_files():
    for name, rule in _grafana_rules().items():
        loki_query = next(d for d in rule["data"] if d["datasourceUid"] == "loki")
        expected = (RULES_DIR / f"{name}.logql").read_text(encoding="utf-8").strip()
        assert loki_query["model"]["expr"].strip() == expected, f"derive sur la regle {name}"


def test_grafana_rules_alert_per_ip_without_noise():
    for rule in _grafana_rules().values():
        assert rule["noDataState"] == "OK"
        assert "source_ip" in rule["annotations"]["summary"]


def test_stuffing_simulation_can_trigger_the_rule():
    valid = {u for u, p in LEAKED_CREDENTIALS if u in USERS and check_password_hash(USERS[u], p)}
    assert len(valid) >= 3
