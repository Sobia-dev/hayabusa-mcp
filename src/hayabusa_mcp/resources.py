"""MCP resources exposing the Sigma rule knowledge base as browsable data.

Three URI schemes:

- ``sigma://rules`` and ``sigma://rules/{rule_id}`` - browse the rules/ knowledge base.
- ``attack://techniques`` and ``attack://techniques/{technique_id}`` - ATT&CK technique
  mappings derived from rule tags, cross-referenced against attack.ATTACK_REFERENCE.
- ``coverage://summary`` - aggregate detection coverage analysis (levels, tactics,
  technique gaps) computed from the two above.

Registered onto a FastMCP instance via register_resources(mcp) rather than decorated
at import time, since the shared `mcp` object lives in server.py.
"""

import json

from mcp.server.fastmcp import FastMCP

from .attack import ATTACK_REFERENCE
from .sigma import find_rule, load_rules


def _rules_by_technique() -> dict[str, list[dict]]:
    mapping: dict[str, list[dict]] = {}
    for rule in load_rules():
        for technique_id in rule.technique_ids:
            mapping.setdefault(technique_id, []).append(rule.summary())
    return mapping


def register_resources(mcp: FastMCP) -> None:
    @mcp.resource(
        "sigma://rules",
        name="sigma-rules-index",
        description="Index of every Sigma rule in the rules/ knowledge base, with id/title/level/ATT&CK tags.",
        mime_type="application/json",
    )
    def list_sigma_rules() -> str:
        rules = load_rules()
        return json.dumps(
            {"count": len(rules), "rules": [rule.summary() for rule in rules]},
            indent=2,
        )

    @mcp.resource(
        "sigma://rules/{rule_id}",
        name="sigma-rule",
        description="Full raw YAML for one Sigma rule, looked up by its `id` field, filename stem, or filename.",
        mime_type="text/yaml",
    )
    def get_sigma_rule(rule_id: str) -> str:
        rule = find_rule(rule_id)
        if rule is None:
            raise ValueError(
                f"No Sigma rule matches '{rule_id}'. "
                "Read sigma://rules for the list of valid ids/filenames."
            )
        return rule.raw_text

    @mcp.resource(
        "attack://techniques",
        name="attack-techniques-index",
        description="ATT&CK techniques referenced by this rule set, each with its covering rule count.",
        mime_type="application/json",
    )
    def list_attack_techniques() -> str:
        by_technique = _rules_by_technique()
        techniques = []
        for technique_id, info in sorted(ATTACK_REFERENCE.items()):
            rules = by_technique.get(technique_id, [])
            techniques.append(
                {
                    "technique_id": technique_id,
                    "name": info["name"],
                    "tactic": info["tactic"],
                    "covered": bool(rules),
                    "rule_count": len(rules),
                    "rule_ids": [r["rule_id"] for r in rules],
                }
            )
        # Also surface any tagged technique that isn't in the curated reference table,
        # so a rule with an unexpected tag doesn't silently disappear from this index.
        for technique_id, rules in sorted(by_technique.items()):
            if technique_id not in ATTACK_REFERENCE:
                techniques.append(
                    {
                        "technique_id": technique_id,
                        "name": "(not in curated ATTACK_REFERENCE)",
                        "tactic": "unknown",
                        "covered": True,
                        "rule_count": len(rules),
                        "rule_ids": [r["rule_id"] for r in rules],
                    }
                )
        return json.dumps({"count": len(techniques), "techniques": techniques}, indent=2)

    @mcp.resource(
        "attack://techniques/{technique_id}",
        name="attack-technique-detail",
        description="Detail for one ATT&CK technique id (e.g. T1003.001): name, tactic, and matching rules.",
        mime_type="application/json",
    )
    def get_attack_technique(technique_id: str) -> str:
        normalized = technique_id.upper()
        by_technique = _rules_by_technique()
        rules = by_technique.get(normalized, [])
        info = ATTACK_REFERENCE.get(normalized)
        if info is None and not rules:
            raise ValueError(
                f"Unknown technique '{technique_id}'. "
                "Read attack://techniques for the list of known technique ids."
            )
        return json.dumps(
            {
                "technique_id": normalized,
                "name": info["name"] if info else "(not in curated ATTACK_REFERENCE)",
                "tactic": info["tactic"] if info else "unknown",
                "covered": bool(rules),
                "rules": rules,
            },
            indent=2,
        )

    @mcp.resource(
        "coverage://summary",
        name="detection-coverage-summary",
        description="Aggregate detection coverage analysis: rule counts by level/status/logsource, "
        "ATT&CK technique coverage percentage, and the list of uncovered reference techniques.",
        mime_type="application/json",
    )
    def coverage_summary() -> str:
        rules = load_rules()
        by_technique = _rules_by_technique()

        by_level: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_logsource_category: dict[str, int] = {}
        for rule in rules:
            by_level[rule.level] = by_level.get(rule.level, 0) + 1
            by_status[rule.status] = by_status.get(rule.status, 0) + 1
            category = rule.logsource.get("category") or rule.logsource.get("service") or "unspecified"
            by_logsource_category[category] = by_logsource_category.get(category, 0) + 1

        covered_ids = {tid for tid in ATTACK_REFERENCE if tid in by_technique}
        gap_ids = sorted(set(ATTACK_REFERENCE) - covered_ids)
        total_reference = len(ATTACK_REFERENCE)
        coverage_percent = round(100 * len(covered_ids) / total_reference, 1) if total_reference else 0.0

        tactics_covered = sorted({ATTACK_REFERENCE[tid]["tactic"] for tid in covered_ids})

        return json.dumps(
            {
                "total_rules": len(rules),
                "rules_by_level": by_level,
                "rules_by_status": by_status,
                "rules_by_logsource": by_logsource_category,
                "tactics_covered": tactics_covered,
                "attack_coverage": {
                    "reference_technique_count": total_reference,
                    "covered_technique_count": len(covered_ids),
                    "coverage_percent": coverage_percent,
                    "covered_techniques": sorted(covered_ids),
                    "gaps": [
                        {"technique_id": tid, "name": ATTACK_REFERENCE[tid]["name"], "tactic": ATTACK_REFERENCE[tid]["tactic"]}
                        for tid in gap_ids
                    ],
                },
            },
            indent=2,
        )
