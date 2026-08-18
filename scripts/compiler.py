#!/usr/bin/env python3
"""Build/test integration for the optimization harness.

The harness's correctness gate is the project's own test suite
(``make -C tests/unit test`` by default). This module runs arbitrary
build/test commands in the project workdir and can also compile a single
``.S`` file into an object file so the disassembler has a fresh artifact to
inspect after every candidate install.
"""

from __future__ import annotations

from pathlib import Path

from common import Result, run_command


class Compiler:
    """Runs build/test commands and single-file assembly compiles."""

    def __init__(self, workdir: Path) -> None:
        self.workdir = workdir

    def run(self, command, timeout: int = 900) -> Result:
        """Run any command with the project root as cwd."""
        return run_command(command, cwd=str(self.workdir), timeout=timeout)

    def test(self, commands) -> Result:
        """Run the correctness test commands in order; first failure stops."""
        # Only wrap a bare string. ``commands`` from arm-optimize.py's
        # default_tests() is already a list (e.g.
        # ["make -C tests/unit test"]) -- wrapping it again produced
        # [["make -C tests/unit test"]], so ``self.run`` received a
        # one-element argv list whose single element was the entire command
        # string. With no shell operator in it, run_command took the
        # non-shell path and tried to exec a program literally named
        # "make -C tests/unit test" (spaces and all) instead of running it
        # through a shell -- "command not found". Commands containing "&&"
        # (every dedicated test_<function> command) masked this: they
        # forced the shell-join path regardless of the extra wrapping.
        if isinstance(commands, str):
            commands = [commands]
        for command in commands:
            result = self.run(command, timeout=1200)
            if not result.success:
                return result
        return Result(success=True, output="(all test commands passed)")

    def compile_object(
        self,
        source: Path,
        out: Path,
        include_dirs: list[str] | None = None,
        arch: str = "arm64",
        opt: str = "-O2",
        debug: str = "-g",
    ) -> Result:
        """Assemble one ``.S`` file into ``out`` (for disassembly only).

        Include dirs are relative to the workdir. The project's unit-test
        Makefile assembles with ``cc -g -O2 -arch arm64 -I ../../src``;
        we mirror that so standalone files (e.g. ``src/util/memcpy.S``)
        assemble exactly like the real build.
        """
        command = ["cc", debug, opt, "-arch", arch]
        for inc in include_dirs or ["src"]:
            command += ["-I", inc]
        command += ["-c", str(source), "-o", str(out)]
        return self.run(command)
