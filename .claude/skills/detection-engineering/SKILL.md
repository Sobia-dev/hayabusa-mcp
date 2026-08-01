---
name: detection-engineering
description: Enforces detection rule standards (ATT&CK mapping, severity justification, false positives, test cases, naming) when writing or reviewing Sigma rules, discussing detection coverage, or working with YAML detection files in rules/.
---

# Detection Engineering Standards

Apply these standards whenever you are:
- Writing or creating Sigma rules
- Reviewing detection rules
- Discussing detection coverage
- Working with YAML detection files

## Required standards

Every Sigma rule in this repository must satisfy all five of the following before it is
considered complete. When writing a new rule, reviewing an existing one, or discussing
coverage, check each item explicitly — do not assume a rule is compliant because it looks
similar to others.

### 1. ATT&CK technique mapping

The rule's `tags` list must include at least one technique tag in the form
`attack.tXXXX` or `attack.tXXXX.XXX` (e.g. `attack.t1003.001`). A tactic-only tag
(`attack.credential-access`) is not sufficient on its own — it must be paired with a
specific technique or sub-technique ID. If the rule genuinely doesn't map to a known
technique, flag this explicitly rather than omitting the tag silently.

### 2. Severity with justification

`level` must be one of exactly: `low`, `medium`, `high`, `critical`. No other values
(e.g. `informational`, `warning`) are acceptable. The rule must also carry a short
justification for that severity — either as a trailing paragraph in `description` or as
a dedicated comment near `level` — explaining *why* this severity was chosen (e.g. "high
because GrantedAccess masks in this range are rarely requested by legitimate processes
and indicate active credential dumping"). A bare `level: high` with no reasoning
anywhere in the rule is incomplete.

### 3. Documented false positive conditions

The rule must have a non-empty `falsepositives` list. Each entry should name a concrete
source of benign activity that could trigger the rule (a specific tool, admin workflow,
or system behavior) — not a vague placeholder like "Unknown" or "None known" unless that
is genuinely true and stated as a deliberate claim, not a default left unfilled.

### 4. At least one test case

The rule must be accompanied by at least one test case demonstrating a log event (or
event fragment) that the detection logic matches, so the rule's `condition` can be
validated against real field values. Record this either as a `falsepositives`-adjacent
`references` entry pointing at a sample, or — preferred — as a sibling file/section
(e.g. a `tests:` block or a `<rule_id>.test.yml` alongside the rule) containing a
minimal representative log record and the expected match result. When reviewing a rule
that has no test case, treat this as a blocking gap, not a nice-to-have.

### 5. Naming convention

Rule filenames must be lowercase with underscores, following the existing pattern of
`<category>_<technique_name>.yml` (e.g. `credential_access_dcsync.yml`,
`lateral_movement_pass_the_hash.yml`). Reject filenames using hyphens, camelCase, or
mixed case. The `title` field is free text and is not subject to this constraint — only
the filename and any internal rule-name identifiers are.

## When reviewing existing rules

Check each of the five items above explicitly and report gaps by name (e.g. "missing
false positive documentation", "level is `warning`, not one of the four allowed
values") rather than a general "looks fine." Existing rules in `rules/` may predate
these standards (in particular, none currently ship with an explicit test case) — treat
that as a gap to flag and fix, not as evidence the standard doesn't apply.

## When discussing detection coverage

Coverage claims should be qualified by standards compliance, not just rule existence —
a rule that lacks an ATT&CK tag doesn't count toward technique coverage even if it
detects the technique in practice, since `coverage://summary` derives tactic/technique
coverage from `attack.tXXXX` tags (see `attack.py` / `sigma.py`).
