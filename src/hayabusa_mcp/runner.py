"""Subprocess wrapper for invoking the Hayabusa binary safely (no shell)."""

import asyncio
from dataclasses import dataclass
from pathlib import Path

from .config import resolve_hayabusa_path

DEFAULT_TIMEOUT_SECONDS = 600


@dataclass
class HayabusaResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


async def run_hayabusa(args: list[str], timeout: int = DEFAULT_TIMEOUT_SECONDS) -> HayabusaResult:
    binary = resolve_hayabusa_path()
    proc = await asyncio.create_subprocess_exec(
        binary,
        *args,
        # Hayabusa resolves its default rule paths (./rules, ./rules/config)
        # relative to the current directory, not the binary's location.
        cwd=str(Path(binary).parent),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        timed_out = False
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        stdout_bytes, stderr_bytes = b"", b""
        timed_out = True

    return HayabusaResult(
        args=args,
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=stdout_bytes.decode(errors="replace"),
        stderr=stderr_bytes.decode(errors="replace"),
        timed_out=timed_out,
    )
