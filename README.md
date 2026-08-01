# hayabusa-mcp

An MCP server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) — a Windows
event log (EVTX) forensics/threat-hunting tool — so an MCP client (e.g. Claude Code, Claude
Desktop) can run timeline, metrics, logon-summary, and search commands against EVTX files and
read the results.

Each tool call shells out to a locally installed `hayabusa` binary, writes its output to a
temp file, and returns the (possibly truncated) content plus the full output file path.

It also doubles as a small **detection engineering knowledge base**: a hand-curated set of
Sigma rules under `rules/` (LSASS memory access, Kerberoasting, DCSync, Pass-the-Hash,
NTDS.dit extraction, Golden Ticket), exposed as MCP *resources* for browsing rule content,
ATT&CK technique mappings, and detection coverage — see [Resources](#resources) below.

## Prerequisites

- Python >= 3.10
- The [Hayabusa](https://github.com/Yamato-Security/hayabusa) binary, downloaded or built
  separately — this project does not bundle it. Extract a release zip (e.g.
  `hayabusa-<version>-win-x64.zip`) somewhere, rename the exe to `hayabusa.exe`, and either
  put its directory on `PATH` or set `HAYABUSA_BIN`. The release zip already includes a
  bundled `rules/` directory, so `update_rules` isn't required to get started.

## Setup

```powershell
cd ~\mcp-hayabusa
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
```

## Configuration (environment variables)

- `HAYABUSA_BIN` — full path to `hayabusa.exe`. If unset, the server looks for `hayabusa.exe`
  / `hayabusa` on `PATH`.
- `HAYABUSA_RULES` — default path to a Sigma rules directory, used by `csv_timeline` /
  `json_timeline` when no `rules` argument is passed.

## Running

```powershell
hayabusa-mcp
```

This starts the server on stdio, ready to be wired into an MCP client config, e.g. for
Claude Code:

```powershell
claude mcp add hayabusa -- python -m hayabusa_mcp.server
```

## Tools

- `csv_timeline` / `json_timeline` — run detection-rule timelines over an EVTX file/directory.
- `logon_summary` — summarize successful/failed logons (writes and returns two CSV files).
- `metrics` — event ID frequency breakdown (runs Hayabusa's `eid-metrics` subcommand).
- `pivot_keywords_list` — extract pivot keywords (users, hosts, IPs) for further hunting
  (writes and returns one file per keyword type).
- `search` — keyword or regex search across EVTX records.
- `update_rules` — pull the latest Sigma detection rules.
- `hayabusa_help` — fetch Hayabusa's own `--help` text for a subcommand.
- `run_raw` — escape hatch to run an arbitrary `hayabusa` argument list.

## Resources

Unlike the tools above, these are read-only MCP *resources* backed by the Sigma rules in
`rules/` — no `hayabusa` binary involved.

- `sigma://rules` — JSON index of every rule in the knowledge base (id, title, level, ATT&CK tags).
- `sigma://rules/{rule_id}` — one rule's full raw YAML, looked up by its Sigma `id`, filename
  stem, or filename (e.g. `sigma://rules/credential_access_dcsync.yml`).
- `attack://techniques` — JSON index of ATT&CK techniques this rule set maps to, with coverage
  (which techniques have a rule, and how many).
- `attack://techniques/{technique_id}` — detail for one technique (e.g. `attack://techniques/T1558.003`):
  name, tactic, and the rules that cover it.
- `coverage://summary` — aggregate detection coverage: rule counts by level/status/logsource,
  ATT&CK tactics covered, and a coverage-percent + gap list of techniques with no rule yet.
