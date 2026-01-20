import sys
from typing import List

from scripts.checks.common import Issue, load_rules, rule_id

MAX_RULE_LENGTH = 255
ALLOWED_NAME_PREFIXES = ("mac-", "win-", "linux-", "c2-", "smb-", "dev")


def run() -> List[Issue]:
    rules = load_rules()
    issues: List[Issue] = []

    for r in rules:
        rid = rule_id(r)
        name = (r.get("name") or "").strip()
        name_l = name.lower()

        if not name:
            issues.append((rid, "Missing name"))
            continue

        if len(name) > MAX_RULE_LENGTH:
            issues.append((rid, f"Name too long ({len(name)} > {MAX_RULE_LENGTH}): {name}"))

        if not any(name_l.startswith(p) for p in ALLOWED_NAME_PREFIXES):
            issues.append((rid, f"Name '{name}' does not start with allowed prefixes {ALLOWED_NAME_PREFIXES}"))

    return issues


if __name__ == "__main__":
    issues = run()
    if issues:
        for rid, msg in issues:
            print(f"- Rule {rid}: {msg}")
        sys.exit(1)  # FAIL the check
    print("OK: prefix/name checks passed")
    sys.exit(0)
