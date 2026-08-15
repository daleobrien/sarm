"""Replace a 16-byte ``ldp``/``stp`` copy loop with a 32-byte NEON loop.

Same idiom detection as :mod:`unroll`; the main loop becomes::

    ld1  {v0.16b, v1.16b}, [<src>], #32
    st1  {v0.16b, v1.16b}, [<dst>], #32

(plus the shared sub/cmp/b.hs counter from :func:`unroll._expand`). The
original 16-byte loop is retained for the 16-31 byte remainder so medium
sizes don't regress to the byte loop. v0/v1 are caller-saved, so the ABI
is untouched.
"""

from __future__ import annotations

from .unroll import _expand, detect_loop


def neon_32b(function_text: str) -> str | None:
    detected = detect_loop(function_text)
    if detected is None:
        return None
    loop = detected[3]

    main_loop = "\n".join(
        [
            f"    ld1 {{v0.16b, v1.16b}}, [{loop.src}], #32",
            f"    st1 {{v0.16b, v1.16b}}, [{loop.dst}], #32",
        ]
    )
    return _expand(function_text, main_loop)
