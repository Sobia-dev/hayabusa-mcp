"""Loads and indexes the Sigma rule knowledge base under ``rules/``.

This is a small curated set of hand-written rules (see rules/), not a mirror of
the full SigmaHQ ruleset that ``update_rules``/``HAYABUSA_RULES`` deal with -
it exists to back the sigma:// and attack:// MCP resources.
"""

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"

_TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


@dataclass
class SigmaRule:
    path: Path
    raw_text: str
    data: dict

    @property
    def rule_id(self) -> str:
        return str(self.data.get("id", self.path.stem))

    @property
    def title(self) -> str:
        return str(self.data.get("title", self.path.stem))

    @property
    def status(self) -> str:
        return str(self.data.get("status", "unknown"))

    @property
    def description(self) -> str:
        return str(self.data.get("description", "")).strip()

    @property
    def level(self) -> str:
        return str(self.data.get("level", "unknown"))

    @property
    def logsource(self) -> dict:
        return dict(self.data.get("logsource", {}))

    @property
    def tags(self) -> list[str]:
        return list(self.data.get("tags", []))

    @property
    def technique_ids(self) -> list[str]:
        ids = []
        for tag in self.tags:
            match = _TECHNIQUE_TAG_RE.match(tag)
            if match:
                ids.append(match.group(1).upper())
        return ids

    def summary(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "filename": self.path.name,
            "title": self.title,
            "status": self.status,
            "level": self.level,
            "logsource": self.logsource,
            "technique_ids": self.technique_ids,
            "tags": self.tags,
        }


def load_rules(rules_dir: Path = RULES_DIR) -> list[SigmaRule]:
    """Parse every .yml/.yaml file in rules_dir into a SigmaRule, sorted by filename.

    Excludes ``*.test.yml``/``*.test.yaml`` sibling files - those hold test cases for
    a rule, not a rule themselves, but would otherwise match the same glob.
    """
    if not rules_dir.exists():
        return []
    paths = [
        p
        for p in list(rules_dir.glob("*.yml")) + list(rules_dir.glob("*.yaml"))
        if not p.stem.endswith(".test")
    ]
    rules = []
    for path in sorted(paths):
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text) or {}
        rules.append(SigmaRule(path=path, raw_text=text, data=data))
    return rules


def find_rule(rule_id: str, rules_dir: Path = RULES_DIR) -> SigmaRule | None:
    """Look up a rule by its Sigma `id`, filename stem, or full filename."""
    for rule in load_rules(rules_dir):
        if rule_id in (rule.rule_id, rule.path.stem, rule.path.name):
            return rule
    return None
