from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

# If this file is scripts/checks/common.py, repo root is 2 parents up
REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_FILE = REPO_ROOT / "rules" / "rules.json"

Rule = Dict[str, Any]
Issue = Tuple[str, str]  # (rule_id, message)


def load_rules() -> List[Rule]:
    if not RULES_FILE.exists():
        raise FileNotFoundError(f"Rules file not found: {RULES_FILE}")

    with RULES_FILE.open(encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        return data
    # Defensive: if someone accidentally makes it a dict, wrap it
    return [data]


def rule_id(rule: Rule) -> str:
    # Use whatever your repo uses (id vs rule_id). Keep both to be safe.
    return str(rule.get("rule_id") or rule.get("id") or "<no-id>")


def parse_timestamp(value: Any) -> datetime | None:
    """Parse ISO 8601 timestamps like 2023-02-28T20:23:14Z"""
    if not value or not isinstance(value, str):
        return None
    cleaned = value.rstrip("Z")
    try:
        return datetime.fromisoformat(cleaned)
    except Exception:
        return None


def iter_strings(obj: Any, prefix: str = "") -> Iterable[Tuple[str, str]]:
    """Recursively yield (path, string) from nested dict/list structures."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else str(k)
            yield from iter_strings(v, p)
    elif isinstance(obj, list):  # <-- list (not "ist")
        for i, v in enumerate(obj):
            p = f"{prefix}[{i}]"
            yield from iter_strings(v, p)
    elif isinstance(obj, str):
        yield (prefix, obj)
