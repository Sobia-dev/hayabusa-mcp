"""Resolves how to locate the Hayabusa binary and its rules directory."""

import os
import shutil

DEFAULT_BIN_NAMES = ("hayabusa.exe", "hayabusa")


def resolve_hayabusa_path() -> str:
    configured = os.environ.get("HAYABUSA_BIN")
    if configured:
        return configured
    for name in DEFAULT_BIN_NAMES:
        found = shutil.which(name)
        if found:
            return found
    raise FileNotFoundError(
        "Could not locate a hayabusa binary. Set the HAYABUSA_BIN environment "
        "variable to its full path, or put hayabusa.exe on PATH."
    )


def resolve_rules_dir() -> str | None:
    return os.environ.get("HAYABUSA_RULES")
