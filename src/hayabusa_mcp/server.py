"""MCP server exposing Hayabusa's EVTX analysis commands as tools."""

import re
import tempfile
import uuid
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .config import resolve_rules_dir
from .resources import register_resources
from .runner import HayabusaResult, run_hayabusa

mcp = FastMCP("hayabusa")
register_resources(mcp)

MAX_OUTPUT_CHARS = 20_000
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _results_dir() -> Path:
    path = Path(tempfile.gettempdir()) / "hayabusa-mcp-results"
    path.mkdir(exist_ok=True)
    return path


def _new_output_path(suffix: str) -> Path:
    return _results_dir() / f"{uuid.uuid4().hex}{suffix}"


def _new_output_prefix() -> Path:
    """For subcommands (logon-summary, pivot-keywords-list) that write multiple
    files named ``<prefix>-<suffix>.csv`` instead of a single output file."""
    return _results_dir() / uuid.uuid4().hex


def _validate_target(target: str) -> Path:
    path = Path(target)
    if not path.exists():
        raise FileNotFoundError(f"Target path does not exist: {target}")
    return path


def _target_args(target: Path) -> list[str]:
    return ["-d", str(target)] if target.is_dir() else ["-f", str(target)]


def _format_failure(result: HayabusaResult) -> str:
    if result.timed_out:
        return f"hayabusa {' '.join(result.args)} timed out."
    return (
        f"hayabusa {' '.join(result.args)} exited with code {result.returncode}.\n"
        f"--- stderr ---\n{_strip_ansi(result.stderr)}\n--- stdout ---\n{_strip_ansi(result.stdout)}"
    )


def _format_output_file(output_path: Path) -> str:
    if not output_path.exists():
        return f"hayabusa reported success but produced no output file at {output_path}."
    content = output_path.read_text(errors="replace")
    total_chars = len(content)
    if total_chars > MAX_OUTPUT_CHARS:
        content = content[:MAX_OUTPUT_CHARS]
        note = (
            f"\n\n[truncated: showing first {MAX_OUTPUT_CHARS} of {total_chars} characters. "
            f"Full output is at {output_path}]"
        )
    else:
        note = f"\n\n[full output saved to {output_path}]"
    return content + note


def _format_prefixed_output(prefix: Path) -> str:
    matches = sorted(prefix.parent.glob(f"{prefix.name}*"))
    if not matches:
        return f"hayabusa reported success but produced no output files with prefix {prefix}."
    parts = []
    remaining = MAX_OUTPUT_CHARS
    for path in matches:
        content = path.read_text(errors="replace")
        if len(content) > max(remaining, 0):
            content = content[: max(remaining, 0)] + f"\n[truncated, full file at {path}]"
        parts.append(f"=== {path.name} ===\n{content}")
        remaining -= len(content)
    return "\n\n".join(parts)


async def _execute(args: list[str], output_path: Path) -> str:
    result = await run_hayabusa(args)
    if result.timed_out or result.returncode != 0:
        return _format_failure(result)
    return _format_output_file(output_path)


async def _execute_prefixed(args: list[str], prefix: Path) -> str:
    result = await run_hayabusa(args)
    if result.timed_out or result.returncode != 0:
        return _format_failure(result)
    return _format_prefixed_output(prefix)


@mcp.tool()
async def csv_timeline(
    target: str,
    rules: str | None = None,
    min_level: str | None = None,
    profile: str | None = None,
    extra_args: list[str] | None = None,
) -> str:
    """Run `hayabusa csv-timeline` against an EVTX file or a directory of EVTX files.

    target: path to a single .evtx file or a directory containing them.
    rules: path to a detection rules directory (falls back to HAYABUSA_RULES env var,
        then to Hayabusa's own bundled ./rules directory).
    min_level: minimum alert level to include ("informational", "low", "medium", "high", "critical").
    profile: Hayabusa output profile name (e.g. "standard", "verbose").
    extra_args: additional raw flags to pass through to hayabusa, e.g. ["--UTC"].

    Returns the resulting CSV timeline (truncated if large) plus the full output file path.
    """
    target_path = _validate_target(target)
    output_path = _new_output_path(".csv")
    args = ["csv-timeline", *_target_args(target_path), "--no-wizard", "-o", str(output_path), "-q", "-K"]
    rules_dir = rules or resolve_rules_dir()
    if rules_dir:
        args += ["-r", rules_dir]
    if min_level:
        args += ["-m", min_level]
    if profile:
        args += ["--profile", profile]
    if extra_args:
        args += extra_args
    return await _execute(args, output_path)


@mcp.tool()
async def json_timeline(
    target: str,
    rules: str | None = None,
    min_level: str | None = None,
    profile: str | None = None,
    extra_args: list[str] | None = None,
) -> str:
    """Same as csv_timeline but runs `hayabusa json-timeline`, producing JSON output."""
    target_path = _validate_target(target)
    output_path = _new_output_path(".json")
    args = ["json-timeline", *_target_args(target_path), "--no-wizard", "-o", str(output_path), "-q", "-K"]
    rules_dir = rules or resolve_rules_dir()
    if rules_dir:
        args += ["-r", rules_dir]
    if min_level:
        args += ["-m", min_level]
    if profile:
        args += ["--profile", profile]
    if extra_args:
        args += extra_args
    return await _execute(args, output_path)


@mcp.tool()
async def logon_summary(target: str, extra_args: list[str] | None = None) -> str:
    """Run `hayabusa logon-summary` to summarize successful/failed logon events.

    Writes two CSV files (successful and failed logons); both are returned.
    """
    target_path = _validate_target(target)
    prefix = _new_output_prefix()
    args = ["logon-summary", *_target_args(target_path), "-o", str(prefix), "-q", "-K"]
    if extra_args:
        args += extra_args
    return await _execute_prefixed(args, prefix)


@mcp.tool()
async def metrics(target: str, extra_args: list[str] | None = None) -> str:
    """Run `hayabusa eid-metrics` to summarize event ID frequency for an EVTX file or directory."""
    target_path = _validate_target(target)
    output_path = _new_output_path(".csv")
    args = ["eid-metrics", *_target_args(target_path), "-o", str(output_path), "-q", "-K"]
    if extra_args:
        args += extra_args
    return await _execute(args, output_path)


@mcp.tool()
async def pivot_keywords_list(target: str, min_level: str | None = None, extra_args: list[str] | None = None) -> str:
    """Run `hayabusa pivot-keywords-list` to extract pivot keywords (users, hosts, IPs, etc.)
    for further hunting. Writes one file per keyword type; all are returned.
    """
    target_path = _validate_target(target)
    prefix = _new_output_prefix()
    args = ["pivot-keywords-list", *_target_args(target_path), "--no-wizard", "-o", str(prefix), "-q", "-K"]
    if min_level:
        args += ["-m", min_level]
    if extra_args:
        args += extra_args
    return await _execute_prefixed(args, prefix)


@mcp.tool()
async def search(target: str, keyword: str, regex: bool = False, extra_args: list[str] | None = None) -> str:
    """Run `hayabusa search` for a keyword or regex pattern across an EVTX file or directory.

    keyword: the literal string (or regex pattern, if regex=True) to search for.
    """
    target_path = _validate_target(target)
    output_path = _new_output_path(".csv")
    flag = "-r" if regex else "-k"
    args = ["search", *_target_args(target_path), flag, keyword, "-o", str(output_path), "-q", "-K"]
    if extra_args:
        args += extra_args
    return await _execute(args, output_path)


@mcp.tool()
async def update_rules() -> str:
    """Run `hayabusa update-rules` to pull the latest Sigma-based detection rules."""
    result = await run_hayabusa(["update-rules"], timeout=120)
    if result.timed_out:
        return "hayabusa update-rules timed out."
    return (
        f"exit code {result.returncode}\n"
        f"--- stdout ---\n{_strip_ansi(result.stdout)}\n--- stderr ---\n{_strip_ansi(result.stderr)}"
    )


@mcp.tool()
async def hayabusa_help(subcommand: str | None = None) -> str:
    """Get Hayabusa's own --help text, optionally scoped to a subcommand (e.g. "csv-timeline").

    Use this to check exact flag names for the installed Hayabusa version before
    resorting to run_raw for something not covered by the other tools.
    """
    args = [subcommand, "--help"] if subcommand else ["--help"]
    result = await run_hayabusa(args, timeout=30)
    return _strip_ansi(result.stdout + result.stderr)


@mcp.tool()
async def run_raw(args: list[str]) -> str:
    """Escape hatch: run hayabusa with an arbitrary argument list, e.g. ["list-profiles"].

    Prefer the dedicated tools (csv_timeline, json_timeline, etc.) when they cover the
    task; use this for subcommands/flags not otherwise exposed. Output is not
    redirected to a file, so large results may be truncated.
    """
    result = await run_hayabusa(args)
    output = (
        f"exit code {result.returncode}\n"
        f"--- stdout ---\n{_strip_ansi(result.stdout)}\n--- stderr ---\n{_strip_ansi(result.stderr)}"
    )
    if len(output) > MAX_OUTPUT_CHARS:
        output = output[:MAX_OUTPUT_CHARS] + "\n[truncated]"
    return output


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
