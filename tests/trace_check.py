#!/usr/bin/env python3
"""Compare a traced syscall set against the allowlist
(docs/SECURITY.md Step 11, called by tests/test_syscalls.sh).

Usage: trace_check.py <allowlist> <seen>
       <seen> is one syscall name per line, as extracted from an strace
       log.  Prints the names that are not allowed, space-separated, and
       nothing at all if the trace is clean.

Two adjustments between what a tracer prints and what the allowlist
lists, both of them the same kernel entry point under a different name:

  * `clone3` is `clone` and `vfork` is `fork` — the same kernel entry
    the allowlist already names, under the name the tracer chose.
  * `rt_sigreturn` is the `sigreturn` the allowlist lists.

Nothing else is folded together.  `recvfrom` is not `read` and
`sendto` is not `write`: sarm calls read(2) and write(2) on a socket, so
the socket-specific variants turning up in a trace would mean something
changed, and that is exactly what this is for.

Startup syscalls that belong to the *tracer* rather than to the traced
program (`execve` of the binary itself, and the loader's `mmap` of it)
are not filtered here.  They are the tracer's own noise on a normally
launched process, and this server is statically linked with no loader —
so if they appear, they are worth seeing, and the test should say so.
"""

import sys

ALIASES = {
    "clone3": "clone",
    "vfork": "fork",
    "rt_sigreturn": "sigreturn",
}


def main():
    if len(sys.argv) != 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    allowed = set()
    with open(sys.argv[1]) as f:
        for line in f:
            s = line.split("#", 1)[0].strip()
            if s:
                allowed.add(s)
    seen = []
    with open(sys.argv[2]) as f:
        for line in f:
            s = line.strip()
            if s:
                seen.append(ALIASES.get(s, s))
    print(" ".join(sorted({n for n in seen if n not in allowed})))
    return 0


if __name__ == "__main__":
    sys.exit(main())
