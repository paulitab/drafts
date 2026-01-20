from pathlib import Path
from datetime import datetime, timedelta
import json
import re

# Local rules file defined in CorrelationRulesClient.__init__
RULES_FILE = Path(__file__).parent.parent / "rules" / "rules.json"

MAX_RULE_LENGTH = 255
MAX_RULE_AGE_DAYS = 365

ALLOWED_NAME_PREFIXES = (
    "mac-",
    "win-",
    "linux-",
    "c2-",
    "smb-",
    "dev",
)

OWNER_FIELDS = ("customer_id", "owner", "rule_owner")

SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
    re.compile(r"password\s*[:=]", re.IGNORECASE),
    re.compile(r"secret\s*[:=]", re.IGNORECASE),
]

def load_rules():
    """Load local correlation rules from rules/rules.json"""
    if not RULES_FILE.exists():
        print(f"[ERROR] Rules file not found: {RULES_FILE}")
        return []

    with RULES_FILE.open(encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        print("[WARN] rules.json is not a list; wrapping in a list for safety")
        return [data]

    return data


def parse_timestamp(value: str):
    """Parse ISO 8601 timestamps like: 2023-02-28T20:23:14Z"""
    if not value:
        return None

    # Remove trailing Z to avoid issues
    if isinstance(value, str):
        cleaned = value.rstrip("Z")
        try:
            return datetime.fromisoformat(cleaned)
        except Exception:
            return None
    return None


def iter_strings(obj, prefix=""):
    """Recursively yield (path, string) pairs from nested dict/lists for secret scanning"""
    if isinstance(obj, dict):
        for key, val in obj.items():
            p = f"{prefix}.{key}" if prefix else key
            yield from iter_strings(val, p)

    elif isinstance(obj, list):
        for idx, val in enumerate(obj):
            p = f"{prefix}[{idx}]"
            yield from iter_strings(val, p)

    elif isinstance(obj, str):
        yield (prefix, obj)


# SAFETY CHECKS

def check_name_length_and_prefix(rules):
    issues = []

    for rule in rules:
        rid = rule.get("rule_id", "<no id>")
        name = rule.get("name", "").lower()

        # too long
        if len(name) > MAX_RULE_LENGTH:
            issues.append((rid, f"Name too long ({len(name)} chars): {name}"))

        # prefix check
        if not any(name.startswith(p) for p in ALLOWED_NAME_PREFIXES):
            issues.append((rid, f"Name '{name}' does not start with an allowed prefix {ALLOWED_NAME_PREFIXES}"))

    return issues


def check_owner_present(rules):
    issues = []

    for rule in rules:
        rid = rule.get("rule_id", "<no id>")
        owner_ok = any(rule.get(field) for field in OWNER_FIELDS)

        if not owner_ok:
            issues.append((rid, f"Missing owner field (checked {OWNER_FIELDS})"))

    return issues


def check_for_secrets(rules):
    issues = []

    for rule in rules:
        rid = rule.get("rule_id", "<no id>")

        for path, string_val in iter_strings(rule):
            for pattern in SECRET_PATTERNS:
                if pattern.search(string_val):
                    issues.append((rid, f"Possible secret at {path}: {pattern.pattern}"))

    return issues


def check_stale_rules(rules):
    """Check if rule last_updated is older than MAX_RULE_AGE_DAYS"""
    issues = []

    cutoff = datetime.utcnow() - timedelta(days=MAX_RULE_AGE_DAYS)

    for rule in rules:
        rid = rule.get("rule_id", "<no id>")
        ts = parse_timestamp(rule.get("last_updated", "") or rule.get("created_on", ""))

        if not ts:
            issues.append((rid, "Could not parse timestamp"))
            continue

        if ts < cutoff:
            issues.append((rid, f"Rule is stale ({ts.isoformat()})"))

    return issues


def main():
    rules = load_rules()

    if not rules:
        print("No rules loaded, nothing to check")
        return

    print(f"Loaded {len(rules)} rules from {RULES_FILE}")

    all_issues = []
    all_issues.extend(check_name_length_and_prefix(rules))
    all_issues.extend(check_owner_present(rules))
    all_issues.extend(check_stale_rules(rules))
    all_issues.extend(check_for_secrets(rules))

    if not all_issues:
        print("No issues found by sanity checks")
        return

    print(f"\nFound {len(all_issues)} potential issues:\n")
    for rid, issue in all_issues:
        print(f"- Rule {rid}: {issue}")


if __name__ == "__main__":
    main()