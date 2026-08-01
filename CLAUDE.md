# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An MCP server with two purposes:

1. It wraps the [Hayabusa](https://github.com/Yamato-Security/hayabusa) EVTX forensics
   binary as MCP tools. It does not implement any EVTX parsing itself — every tool call
   shells out to a locally installed `hayabusa` binary and returns its output.
2. It is a **detection engineering knowledge base**: a small, hand-curated set of Sigma
   rules under `rules/` (credential access / lateral movement techniques — LSASS dumping,
   Kerberoasting, DCSync, Pass-the-Hash, NTDS.dit extraction, Golden Ticket), exposed as
   browsable MCP *resources* (not tools) so a client can read rule content, look up
   ATT&CK technique mappings, and pull a detection-coverage summary without invoking
   Hayabusa at all. See "Detection knowledge base" below.

## Setup / run

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
hayabusa-mcp                 # runs the server on stdio
```

There is no test suite or lint config in this repo yet.

Register with an MCP client (e.g. Claude Code) via:

```powershell
claude mcp add hayabusa -- python -m hayabusa_mcp.server
```

## Configuration

- `HAYABUSA_BIN` — full path to `hayabusa.exe`; falls back to searching `PATH` for
  `hayabusa.exe` / `hayabusa` (see `config.resolve_hayabusa_path`).
- `HAYABUSA_RULES` — default Sigma rules directory, used by `csv_timeline`/`json_timeline`
  when no `rules` argument is given (see `config.resolve_rules_dir`).

## Detection knowledge base

`rules/` holds the curated Sigma rules (plain YAML, standard Sigma fields: `id`, `title`,
`status`, `logsource`, `detection`, `tags`, `level`, ...). ATT&CK technique tags follow
Sigma convention: `attack.t1003.001`. This is a separate, small (~6 rule) set for browsing
and coverage analysis — it is unrelated to `HAYABUSA_RULES` / `update_rules`, which point at
the full SigmaHQ ruleset Hayabusa actually scans EVTX with.

Three MCP resource URI schemes, registered by `resources.py`:

- `sigma://rules` (index, JSON) and `sigma://rules/{rule_id}` (one rule's raw YAML, looked
  up by its Sigma `id`, filename stem, or filename) — browse the rule set.
- `attack://techniques` (index, JSON) and `attack://techniques/{technique_id}` (JSON detail)
  — ATT&CK technique mappings, built by scanning rule tags at read time (not cached).
- `coverage://summary` (JSON) — rule counts by level/status/logsource, ATT&CK tactics
  covered, and a coverage-percent + gap list computed against the curated technique
  reference table in `attack.py`.

`attack.py`'s `ATTACK_REFERENCE` is a hand-picked table of credential-access /
lateral-movement techniques (not a full ATT&CK Enterprise mirror) — it exists so
`coverage://summary` can report *which of the techniques we care about have no rule yet*,
not just describe the rules that already exist. Extend it when adding rules for techniques
outside that neighborhood.

`sigma.py` does the YAML loading/parsing (`load_rules`, `find_rule`) and derives
`technique_ids` from each rule's `attack.tNNNN[.NNN]` tags via regex — it has no dependency
on `resources.py` or `attack.py`, so it can be reused if more resource types are added later.

## Architecture

Module split, one responsibility each:

- `config.py` — resolves the Hayabusa binary path and default rules directory from env vars.
- `runner.py` — `run_hayabusa(args)` spawns the binary via
  `asyncio.create_subprocess_exec` with an argument list (never a shell string, so nothing
  from tool arguments can be interpreted as shell syntax). Returns a `HayabusaResult`
  (stdout/stderr/returncode/timed_out).
- `sigma.py` / `attack.py` / `resources.py` — the detection knowledge base (see above).
- `server.py` — defines the FastMCP server (`mcp = FastMCP("hayabusa")`), calls
  `register_resources(mcp)`, and defines all `@mcp.tool()` functions.

Tool call flow: validate the `target` path exists → build hayabusa CLI args by hand per
subcommand (each tool constructs its own arg list — flag support genuinely differs per
subcommand, see below) → run via `runner.run_hayabusa` → on success, read the result back
(`server._execute` for single-output-file subcommands, `server._execute_prefixed` for
subcommands that write multiple files off a prefix) and return truncated content
(`MAX_OUTPUT_CHARS`) with a note pointing at the full file path(s); on failure/timeout,
return stderr+stdout (`server._format_failure`). Output accumulates under
`%TEMP%\hayabusa-mcp-results\` — it is not cleaned up automatically.
`runner.run_hayabusa` runs the subprocess with `cwd` set to the Hayabusa binary's own
directory, since Hayabusa resolves its default `./rules` / `./rules/config` paths relative
to the process cwd, not the binary's location.

Hayabusa's subcommand flags are *not* uniform — this was discovered by diffing this code
against `hayabusa <subcommand> --help` on the real v3.10.0 CLI, not assumed:
- `csv-timeline` / `json-timeline` support `--no-wizard` (required, or the CLI blocks on an
  interactive prompt), `-r/--rules`, `-m/--min-level`, `-p/--profile`, and a single `-o` output
  file.
- `pivot-keywords-list` supports `--no-wizard` and `-m/--min-level` but has **no** `-r/--rules`
  or `--profile` flag, and its `-o` is a filename *prefix* — it writes one file per keyword
  type (e.g. `<prefix>-IP Addresses.txt`).
- `logon-summary` has none of `--no-wizard`/`-r`/`-m`/`--profile`, and its `-o` is also a
  prefix, writing `<prefix>-successful.csv` and `<prefix>-failed.csv`.
- `eid-metrics` (not `metrics` — there is no `metrics` subcommand) has none of those either,
  and its `-o` is a single normal output file.
- `search` uses `-k`/`-r` for keyword vs. regex (note: `-r` means regex here, not rules) plus
  a single `-o` output file.

Before adding a new tool or changing flags, check `hayabusa_help` against the installed
binary rather than assuming a flag exists on a subcommand because it exists on another one.

Two escape hatches exist for this reason: `hayabusa_help` (runs `hayabusa --help` or
`hayabusa <subcommand> --help`) to check real flag names, and `run_raw` to invoke any
subcommand/argument list directly.
