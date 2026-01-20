import sys
from typing import List

from scripts.checks.common import Issue, load_rules, rule_id


def run() -> List[Issue]:
    rules = load_rules()
    issues: List[Issue] = []

    for r in rules:
        rid = rule_id(r)
        owner = (r.get("owner") or "").strip()
        if not owner:
            issues.append((rid, "Missing required field: owner"))

    return issues


if __name__ == "__main__":
    issues = run()
    if issues:
        for rid, msg in issues:
            print(f"- Rule {rid}: {msg}")
        sys.exit(1)
    print("OK: owner check passed")
    sys.exit(0)
