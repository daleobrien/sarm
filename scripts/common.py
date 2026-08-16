#!/usr/bin/env python3
"""Shared helpers for the sarm AArch64 optimization harness.

Implements the "LLM proposes -> assembler builds -> tests prove correctness
-> benchmark measures -> keep only improvements" loop described in
OPTIMISATION.MD. This module only holds cross-cutting utilities; the
actual stages live in their own modules.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Sequence


@dataclass
class Result:
    """Outcome of a subprocess invocation."""

    success: bool
    output: str = ""
    error: str = ""
    returncode: int = -1

    def summary(self, limit: int = 4000) -> str:
        text = (self.output + "\n" + self.error).strip()
        if len(text) > limit:
            text = text[:limit] + "\n... (truncated)"
        return text


# Shell operators that force us to run through a shell.
_SHELL_OPERATORS = ("&&", "||", ";", "|", ">", "<", "&", "`", "$(")


def needs_shell(command: Sequence[str]) -> bool:
    """True if an argv list contains shell syntax we cannot pass verbatim."""
    return any(any(op in tok for op in _SHELL_OPERATORS) for tok in command)


def run_command(
    command: Sequence[str] | str,
    cwd: str | None = None,
    timeout: int = 600,
    env: dict[str, str] | None = None,
) -> Result:
    """Run a command and capture its output.

    ``command`` may be:

    * an argv list (``["make", "-C", "tests/unit", "test"]``), executed
      directly, or through a shell if it contains shell operators; or
    * a single string, executed through ``sh -c``.

    Returns a :class:`Result`; a timeout or missing executable yields a
    failed result rather than raising.
    """
    shell = isinstance(command, str)
    if not shell:
        shell = needs_shell(command)
        argv: Sequence[str] | str = list(command)
    else:
        argv = command

    try:
        started = time.monotonic()
        proc = subprocess.run(
            argv,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            shell=shell,
        )
        return Result(
            success=proc.returncode == 0,
            output=proc.stdout,
            error=proc.stderr,
            returncode=proc.returncode,
        )
    except subprocess.TimeoutExpired as exc:
        return Result(success=False, error=f"timeout after {timeout}s ({exc})")
    except FileNotFoundError as exc:
        return Result(success=False, error=f"command not found: {exc}")
    except OSError as exc:
        return Result(success=False, error=f"failed to run command: {exc}")


def detect_tool(*names: str) -> str | None:
    """Return the path of the first tool on PATH, or None."""
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


def to_command(value: Sequence[str] | str) -> str:
    """Render a command (argv list or string) for display/logging."""
    if isinstance(value, str):
        return value
    return " ".join(shlex.quote(tok) for tok in value)
