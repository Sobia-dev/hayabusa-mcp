---
name: query
description: Search the Sigma rule / ATT&CK knowledge base (sigma://, attack://) for a technique ID, keyword, or rule name and summarize findings as investigation notes.
argument-hint: <search-term>
---

You are answering a detection-engineering lookup against this repo's curated knowledge
base, exposed as MCP resources (not tools) — no Hayabusa binary invocation is involved.

Search term: `$ARGUMENTS`

## Steps

1. Read `sigma://rules` to get the full rule index (id, title, level, status, ATT&CK tags).
2. Read `attack://techniques` to get the full technique index (technique_id, name, tactic,
   covered, rule_count).
3. Match `$ARGUMENTS` against both, trying each interpretation that applies:
   - **Technique ID** (e.g. `T1003.001`, `t1558.003`, or bare `1003.001`) — normalize to
     `TNNNN[.NNN]` uppercase and look for an exact or prefix match in the technique index
     (e.g. `T1003` should surface all `T1003.*` sub-techniques).
   - **Keyword** — case-insensitive substring match against rule `title`, `id`, and
     technique `name`/`tactic` (e.g. "kerberoast", "dcsync", "lsass", "golden ticket",
     "credential-access").
   - **Rule name** — match against rule `id` or filename-style title.
4. For every matching rule, read `sigma://rules/{rule_id}` to pull its full YAML so you can
   report level, status, logsource, and the `falsepositives`/`references` fields if present.
5. For every matching or related technique, note its `covered` state and `rule_count` from
   the attack index — no need to fetch `attack://techniques/{technique_id}` individually
   unless you need detail beyond what the index already returned.
6. If nothing matches directly, do NOT fetch `coverage://summary` speculatively — instead
   compute the closest related technique/rule yourself from the two indexes already read
   (e.g. shared tactic, shared technique family, or fuzzy string closeness on title/name),
   and say plainly that no direct match was found.

## Output format

Produce investigation notes in this shape:

```
# Investigation Notes: <search term>

## Findings
<For each matching rule:>
- **<rule title>** (`<rule id>`) — level: <level>, status: <status>
  - Logsource: <category/service/product as applicable>
  - ATT&CK: <technique id(s)> — <technique name(s)>
  - False positives: <from rule YAML, or "none documented">

<If no rules matched but a technique matched:>
- No Sigma rule currently covers `<technique id>` (<technique name>) — coverage gap.

<If nothing matched at all:>
- No matching rules or techniques found for "<search term>".

## Related techniques
<Bullet list of ATT&CK techniques adjacent to the findings — same tactic, same technique
family (e.g. other T1003.* sub-techniques), or the closest fuzzy match — each with
technique_id, name, and covered/uncovered status.>
```

Keep it factual and grounded only in what the two resources actually returned — do not
invent rule ids, technique ids, or coverage claims. If the search term is ambiguous between
a technique ID and a keyword, run both interpretations and report whichever produced
matches (or both, if both did).
