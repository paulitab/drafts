import sys
from datetime import datetime, timedelta
from typing import List

from scripts.checks.common import Issue, load_rules, parse_timestamp, rule_id

MAX_RULE_AGE_DAYS = 365


def run() -> List[Issue]:
    rules = load_rules()
    issues: List[Issue] = []
    cutoff = datetime.utcnow() - timedelta(days=MAX_RULE_AGE_DAYS)

    for r in rules:
        rid = rule_id(r)

        ts = (
            parse_timestamp(r.get("last_updated"))
            or parse_timestamp(r.get("updated_on"))
            or parse_timestamp(r.get("created_on"))
        )

        if not ts:
            issues.append((rid, "Could not parse timestamp (expected last_updated/updated_on/created_on)"))
            continue

        if ts < cutoff:
            issues.append((rid, f"Rule is stale: {ts.isoformat()} (< cutoff {cutoff.isoformat()})"))

    return issues


if __name__ == "__main__":
    issues = run()
    if issues:
        for rid, msg in issues:
            print(f"- Rule {rid}: {msg}")
        sys.exit(1)
    print("OK: stale check passed")
    sys.exit(0)
