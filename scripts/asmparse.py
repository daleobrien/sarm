#!/usr/bin/env python3
"""Shared AArch64 assembly parser for sarm's analysis tooling.

Everything that reads ``.S`` files -- ``abi.py``, ``regpressure.py``,
``validate_clobbers.py`` -- parses assembly through this module. It exists
because there used to be two parsers, and the divergence between them hid a
soundness bug for a long time:

``abi.py`` discarded every line beginning with ``.`` *before* it tested for a
label, so all 393 ``.L...`` local labels in ``src/`` were invisible. Branch
targets did not resolve, back edges vanished, no loop was ever detected, and
the ABI checker's central claim -- "callee-saved registers are restored on
*every* path to ``ret``" -- rested on a control-flow graph that, for most
functions in this repo, had almost no edges.

The module provides four things:

* **Parsing** -- ``parse_instructions`` matches labels *before* directives, so
  ``.Lfoo:`` is a label and ``.align 2`` is a directive. ``resolve_target``
  resolves branch targets including numeric local labels (``2b`` / ``3f``).
* **Macro expansion** -- ``src/defs.S`` defines 13 macros used ~500 times.
  ``ldr_l``/``str_l`` write a hidden scratch register (``x9`` by default) and
  ``SCWISVC`` expands to ``svc``, which clobbers the caller-saved registers.
  Unexpanded, liveness misses those writes and every syscall site looks like
  straight-line code. Expansion is platform-aware: Linux puts the syscall
  number in x8, macOS in x16.
* **Region discovery** -- a *callable region* is any label reached by ``bl``,
  whether or not it carries ``.global``. ``.Lgcm_ghash_run`` in
  ``src/crypto/gcm/data.S`` is the real GHASH implementation (the ``.global
  ghash`` symbol is never called by AES-GCM), and it is a local label. The
  analysis unit is the region, not the ``.global`` symbol.
* **Call graph** -- who calls what, so a symbol that nothing calls is not
  mistaken for a hot path.
"""

from __future__ import annotations

import platform
import re
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

# ----------------------------------------------------------------------
# Lines, labels and directives
# ----------------------------------------------------------------------

# Files that are data tables or shared headers, not code.
SKIP_FILES = {
    "config.S", "defs.S", "embedded.S", "cert_data.S", "h2_huffman_table.S",
}

# A label is "name:" at the start of a line. ".Lfoo:" and "9900:" are labels;
# ".align 2" is not, because the directive name is not followed by a colon.
LABEL_RE = re.compile(r"^(\.?[A-Za-z0-9_.$]+):\s*(.*)$")

# Directive names that must never be mistaken for labels even if some future
# spelling puts a colon after them.
DIRECTIVE_RE = re.compile(
    r"^\.(align|p2align|balign|text|data|bss|globa?l|equ|set|byte|hword|short|"
    r"word|long|quad|octa|single|double|float|section|subsection|macro|endm|"
    r"asciz|ascii|string|space|skip|fill|zero|rept|irp|endr|type|size|extern|"
    r"weak|hidden|protected|comm|lcomm|cfi_\w+|loc|file|ident|pushsection|"
    r"popsection|include|if\w*|else|endif|arch|cpu|abort)\b"
)

# Directives that emit data rather than instructions.
DATA_DIRECTIVE_RE = re.compile(
    r"^\.(byte|hword|short|word|long|quad|octa|single|double|float|asciz|"
    r"ascii|string|space|skip|fill|zero|comm|lcomm)\b"
)

GLOBAL_RE = re.compile(r"^\.globa?l\s+([A-Za-z0-9_.$]+)")

# Almost nothing in this repo declares a symbol with a bare label. ``src/defs.S``
# wraps that in a macro -- ``FUNC h2_stream_find`` expands to ``.global
# h2_stream_find`` followed by ``h2_stream_find:``, and ``OBJECT`` does the same
# for data -- and src/ uses those 176 and 124 times respectively.
#
# Macro expansion alone does not cover it. Expansion feeds the *instruction*
# stream, but region discovery runs over the raw lines and must: every extent,
# doc-comment block and reported line number is a raw line index, so expanding
# first would silently shift all of them. The two halves therefore disagreed --
# ``bl`` targets were found in expanded text, symbols in raw text -- and the
# index ended up holding only the 23 ``.L`` labels that some ``bl`` names
# directly. Every ``.global`` symbol in the repo was invisible, so ``abi.py``
# could not find a single function to check, ``regpressure.py`` reported
# "region not found" for all of them, and ``validate_clobbers.py`` saw 12 of
# the 200+ ``// Clobbered Registers:`` headers. The gates passed because they
# were checking nothing.
SYMBOL_MACRO_RE = re.compile(r"^(?:FUNC|OBJECT)\s+([A-Za-z0-9_.$]+)\s*$")


def symbol_macro(line: str) -> str | None:
    """Return the symbol a comment-stripped ``FUNC``/``OBJECT`` line declares."""
    match = SYMBOL_MACRO_RE.match(line)
    return match.group(1) if match else None


# The four symbol-typing macros are directives wearing an instruction's
# shape: no mnemonic table has them, and on Apple hosts ``ENDFUNC``
# expands to nothing at all. They must not reach ``parse_instructions``
# as instructions -- a trailing ``ENDFUNC sym`` is the last "instruction"
# of all 187 FUNC regions in the tree, which hid every real ``ret`` from
# the fallthrough check in ``scan_regions`` and chained 17 functions into
# successors control never reaches.
SYMBOL_DIRECTIVE_RE = re.compile(
    r"^(?:FUNC|ENDFUNC|OBJECT|ENDOBJ)\s+[A-Za-z0-9_.$]+\s*$"
)

# Lines that belong to a region's *header* rather than to the previous
# region's body: the doc comment block, blank lines, and the alignment /
# visibility directives that immediately precede the label.
HEADER_DIRECTIVE_RE = re.compile(
    r"^\.(align|p2align|balign|globa?l|type|size|extern|weak|hidden|"
    r"protected|text|section|cfi_\w+)\b"
)


def strip_comment(line: str) -> str:
    """Remove ``//`` and ``/* */`` comments from a line."""
    for marker in ("//", "/*"):
        idx = line.find(marker)
        if idx != -1:
            line = line[:idx]
    return line.strip()


def is_label(line: str) -> tuple[str, str] | None:
    """Return ``(name, rest)`` if a comment-stripped line defines a label."""
    if DIRECTIVE_RE.match(line):
        return None
    match = LABEL_RE.match(line)
    if not match:
        return None
    return match.group(1), match.group(2).strip()


@dataclass
class Instruction:
    line: int
    text: str
    mnemonic: str
    operands: list[str]

    def regs(self) -> list[str]:
        """All registers mentioned in the operand text."""
        regs: list[str] = []
        for operand in self.operands:
            for match in REG_RE.finditer(operand):
                regs.append(match.group(1))
        return regs


REG_RE = re.compile(
    r"\b(x\d+|w\d+|v\d+|d\d+|q\d+|s\d+|b\d+|h\d+|sp|wsp|xzr|wzr)\b"
)


def parse_instructions(
    source: str,
) -> tuple[list[Instruction], dict[str, list[int]]]:
    """Parse an assembly body into instructions and a ``label -> indices`` map.

    The index a label maps to is the index of the *next* instruction, which is
    what branch resolution wants. Labels are matched before directives are
    discarded -- that is the whole point of this function.

    A label may be defined more than once in one body, and the map keeps every
    definition. Numeric local labels (``9900:``) are *meant* to repeat -- the
    ``SCERR`` macro expands to a pair of them at every syscall site, so a
    function with two syscalls defines each of them twice, and ``2b``/``3f``
    resolution only means anything if all the definitions are visible. Named
    labels repeat too, in a file where the two arms of an ``#ifdef`` both
    define one: nothing here runs the preprocessor, so both arms are parsed
    and both definitions are real as far as this parser is concerned.
    Collapsing either kind to one entry silently wired branches to the wrong
    target -- in ``detect_cpus`` it routed the Linux arm's error path into the
    macOS arm's epilogue and reported a stack imbalance that does not exist.
    """
    instructions: list[Instruction] = []
    labels: dict[str, list[int]] = {}

    for lineno, raw in enumerate(source.splitlines(), start=1):
        line = strip_comment(raw)
        if not line:
            continue
        # Several labels may share a line ("1: 2: instruction"), and a label
        # may sit alone on its own line.
        while True:
            found = is_label(line)
            if not found:
                break
            name, rest = found
            labels.setdefault(name, []).append(len(instructions))
            line = rest
            if not line:
                break
        if not line:
            continue
        if line.startswith("#") or line.startswith("."):
            continue
        if SYMBOL_DIRECTIVE_RE.match(line):
            continue
        parts = line.split(None, 1)
        mnemonic = parts[0]
        operands: list[str] = []
        if len(parts) > 1:
            operands = [op.strip() for op in split_operands(parts[1])]
        instructions.append(Instruction(lineno, raw, mnemonic, operands))

    return instructions, labels


def split_operands(text: str) -> list[str]:
    """Split an operand list on commas that are not inside ``[]`` or ``{}``."""
    out: list[str] = []
    depth = 0
    current: list[str] = []
    for char in text:
        if char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
        if char == "," and depth <= 0:
            out.append("".join(current))
            current = []
            continue
        current.append(char)
    if current:
        out.append("".join(current))
    return [o.strip() for o in out if o.strip()]


def resolve_target(target: str, labels: dict[str, list[int]],
                   current: int) -> int | None:
    """Resolve a branch target, including numeric local labels (``2b``/``3f``).

    ``current`` is the index of the branching instruction; ``2b`` means the
    nearest preceding definition of label ``2``, ``3f`` the nearest following.

    A name defined more than once resolves the same way a local label does:
    the nearest definition at or after the branch, else the nearest one before
    it. For the single definition that names almost always have, that is the
    definition itself; for the two arms of an ``#ifdef``, it is the arm the
    branch is written in.
    """
    target = target.strip()
    if len(target) > 1 and target[-1] in "bf" and target[:-1].isdigit():
        name, direction = target[:-1], target[-1]
        values = labels.get(name, [])
        if direction == "b":
            before = [v for v in values if v <= current]
            return max(before) if before else None
        after = [v for v in values if v > current]
        return min(after) if after else None

    values = labels.get(target, [])
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    after = [v for v in values if v >= current]
    return min(after) if after else max(values)


# ----------------------------------------------------------------------
# Macro expansion
# ----------------------------------------------------------------------

@dataclass
class Macro:
    name: str
    params: list[tuple[str, str | None]]  # (name, default)
    body: list[str]


def host_is_linux() -> bool:
    return platform.system() == "Linux"


def parse_macros(defs_text: str, *, linux: bool | None = None) -> dict[str, Macro]:
    """Parse ``.macro`` definitions from ``defs.S`` for one platform.

    ``defs.S`` defines each syscall/relocation helper twice inside an
    ``#ifdef __linux__`` / ``#else``; only the active branch is kept, because
    the two differ in ways that matter to the analysis (Linux puts the syscall
    number in x8, Darwin in x16).
    """
    if linux is None:
        linux = host_is_linux()

    macros: dict[str, Macro] = {}
    branch: list[bool] = []
    active = True
    current: Macro | None = None

    for raw in defs_text.splitlines():
        line = raw.strip()

        if line.startswith("#ifdef __linux__"):
            branch.append(linux)
            active = all(branch)
            continue
        if line.startswith("#ifndef __linux__"):
            branch.append(not linux)
            active = all(branch)
            continue
        if line.startswith("#else") and branch:
            branch[-1] = not branch[-1]
            active = all(branch)
            continue
        if line.startswith("#endif") and branch:
            branch.pop()
            active = all(branch)
            continue

        if current is not None:
            if line.startswith(".endm"):
                if active:
                    macros[current.name] = current
                current = None
            else:
                current.body.append(raw)
            continue

        if line.startswith(".macro"):
            decl = strip_comment(line)[len(".macro"):].strip()
            # ".macro adr_l, reg, sym" and ".macro ldr_l reg, sym, scratch=x9"
            head, _, rest = decl.partition(" ")
            name = head.rstrip(",")
            params: list[tuple[str, str | None]] = []
            for part in rest.split(","):
                part = part.strip()
                if not part:
                    continue
                pname, eq, default = part.partition("=")
                params.append((pname.strip(), default.strip() if eq else None))
            current = Macro(name=name, params=params, body=[])

    return macros


def expand_macros(text: str, macros: dict[str, Macro], depth: int = 4) -> str:
    """Recursively expand macro invocations in an assembly body.

    A macro invocation may sit after a label ("``1: SCWISVC``"), so the label
    is preserved and the expansion follows it.
    """
    if not macros:
        return text
    for _ in range(depth):
        out: list[str] = []
        changed = False
        for raw in text.splitlines():
            stripped = strip_comment(raw)
            if not stripped:
                out.append(raw)
                continue

            prefix = ""
            while True:
                found = is_label(stripped)
                if not found:
                    break
                name, rest = found
                prefix += name + ":\n"
                stripped = rest
                if not stripped:
                    break

            head, _, argtext = stripped.partition(" ")
            macro = macros.get(head.rstrip(","))
            if macro is None:
                out.append(raw)
                continue

            args = split_operands(argtext)
            bindings: dict[str, str] = {}
            for i, (pname, default) in enumerate(macro.params):
                if i < len(args):
                    bindings[pname] = args[i]
                elif default is not None:
                    bindings[pname] = default
                else:
                    bindings[pname] = ""

            if prefix:
                out.append(prefix.rstrip("\n"))
            for body_line in macro.body:
                expanded = body_line
                # Longest parameter names first so \s does not eat \scratch.
                for pname in sorted(bindings, key=len, reverse=True):
                    expanded = expanded.replace("\\" + pname, bindings[pname])
                out.append(expanded)
            changed = True

        text = "\n".join(out)
        if not changed:
            break
    return text


def load_macros(root: Path | None = None, *,
                linux: bool | None = None) -> dict[str, Macro]:
    """Load every ``.macro`` in ``src/`` for the given (default: host) platform.

    ``defs.S`` holds the 13 shared macros, but subsystems define their own --
    ``gcm_rbit`` in ``crypto/gcm/data.S``, the ``carry51`` family in
    ``crypto/x25519/*.S``. Those expand to real arithmetic (and to carry
    chains), so leaving them as opaque one-line "instructions" would hide
    exactly the register writes and flag writes this tooling exists to see.
    """
    root = root or ROOT
    macros: dict[str, Macro] = {}
    defs = root / "src" / "defs.S"
    if defs.exists():
        macros.update(parse_macros(defs.read_text(errors="replace"),
                                   linux=linux))
    for path in sorted((root / "src").rglob("*.S")):
        if path == defs:
            continue
        text = path.read_text(errors="replace")
        if ".macro" not in text:
            continue
        for name, macro in parse_macros(text, linux=linux).items():
            macros.setdefault(name, macro)
    return macros


# ----------------------------------------------------------------------
# Regions: the unit of analysis
# ----------------------------------------------------------------------

@dataclass
class Region:
    """A callable unit of assembly: a label plus the code that follows it.

    A region is *not* the same thing as a ``.global`` symbol. Any label that
    something reaches with ``bl`` is a region, including file-local ``.L...``
    labels -- ``.Lgcm_ghash_run`` is the real GHASH implementation and has no
    ``.global``.
    """
    name: str
    path: Path
    label_line: int          # 1-based line of the label itself
    start_line: int          # 1-based line where the doc header starts
    end_line: int            # 1-based, exclusive
    text: str                # doc header + body
    body: str                # from the label line onwards
    doc: str                 # the ``//`` comment header, comment markers kept
    is_global: bool
    is_local_label: bool
    # Set when the region's last instruction is not a terminator, i.e. control
    # runs on into the region below it (p256_fe_sqr falls through into
    # p256_fe_mul). The fallthrough body is appended before analysis.
    falls_through_to: str | None = None
    # Name of the top-level region this one is textually nested inside, if
    # any. ``hex_to_val`` is a bl target sitting in the middle of
    # ``decode_url``'s body; it is a callable region of its own, but
    # ``decode_url``'s prologue/epilogue still surround it.
    enclosing: str | None = None

    @property
    def rel(self) -> str:
        try:
            return str(self.path.relative_to(ROOT))
        except ValueError:
            return str(self.path)

    def carry_abi(self) -> bool:
        """Does this region return its status in the carry flag?

        55 source files document the convention "carry clear = success /
        carry set = failure". For those functions NZCV is a live-out value
        and part of the ABI.
        """
        return bool(re.search(r"carry\s+(set|clear)", self.doc, re.I))

    def documented_clobbers(self) -> str | None:
        """The raw text of the ``// Clobbered Registers:`` header field."""
        return doc_field(self.doc, "Clobbered Registers")


def doc_field(doc: str, field_name: str) -> str | None:
    """Extract one ``// Field Name:`` block from a doc comment header."""
    lines = doc.splitlines()
    collected: list[str] = []
    capturing = False
    for raw in lines:
        text = raw.strip()
        if text.startswith("//"):
            text = text[2:].strip()
        if not capturing:
            if text.startswith(field_name + ":"):
                capturing = True
                rest = text[len(field_name) + 1:].strip()
                if rest:
                    collected.append(rest)
            continue
        # A new field, a rule line, or a blank line ends the block.
        if not text or set(text) <= {"-", "─", "="}:
            break
        if re.match(r"^[A-Z][A-Za-z/ ]+:", text):
            break
        collected.append(text)
    if not capturing:
        return None
    return " ".join(collected).strip()


def _classify_lines(text: str) -> tuple[list[tuple[int, str, bool]], set[str],
                                        set[int]]:
    """One pass over a file.

    Returns ``(labels, globals, data_label_lines)`` where ``labels`` is a list
    of ``(line_index, name, is_data_label)``.
    """
    lines = text.splitlines()
    labels: list[tuple[int, str, bool]] = []
    globals_: set[str] = set()

    for i, raw in enumerate(lines):
        line = strip_comment(raw)
        if not line:
            continue
        match = GLOBAL_RE.match(line)
        if match:
            globals_.add(match.group(1))
            continue
        declared = symbol_macro(line)
        if declared:
            # FUNC/OBJECT are both halves at once: the .global and the label.
            globals_.add(declared)
            labels.append((i, declared, False))
            continue
        found = is_label(line)
        if found:
            labels.append((i, found[0], False))

    # A label is a *data* label when the first thing after it (skipping blank
    # lines, comments and alignment) emits data rather than an instruction.
    resolved: list[tuple[int, str, bool]] = []
    data_lines: set[int] = set()
    for i, name, _ in labels:
        is_data = False
        for j in range(i, len(lines)):
            line = strip_comment(lines[j])
            # Strip any labels on this line: several data symbols may alias
            # the same address ("sha256_ctx:" / "sha256_ctx_state: .skip 32"),
            # and what decides the question is the first *content* below.
            while line:
                found = is_label(line)
                if not found:
                    break
                line = found[1]
            if not line:
                continue
            # The FUNC/OBJECT line is the declaration, not the content that
            # decides code-vs-data; what follows it is. Skipping it is what
            # lets `OBJECT h2_streams` + `.skip ...` read as data.
            if symbol_macro(line):
                continue
            if HEADER_DIRECTIVE_RE.match(line):
                continue
            is_data = bool(DATA_DIRECTIVE_RE.match(line))
            break
        resolved.append((i, name, is_data))
        if is_data:
            data_lines.add(i)
    return resolved, globals_, data_lines


FUNCTION_NAME_RE = re.compile(
    r"^//\s*Function Name:\s*([A-Za-z0-9_.$]+)")


def _doc_blocks(lines: list[str]) -> dict[str, str]:
    """Map ``// Function Name: X`` doc blocks to X.

    The doc header is not always adjacent to the label it describes: in
    ``util/itoa.S`` a ``.bss`` buffer definition sits between them, and in the
    x25519 files the per-macro headers are interleaved with the function's.
    Keying blocks by the name they declare is more reliable than assuming
    adjacency.
    """
    blocks: dict[str, str] = {}
    current: list[str] = []

    def flush() -> None:
        if not current:
            return
        for line in current:
            match = FUNCTION_NAME_RE.match(line.strip())
            if match:
                blocks.setdefault(match.group(1), "\n".join(current))
                break
        current.clear()

    for raw in lines:
        if raw.strip().startswith("//"):
            current.append(raw)
        else:
            flush()
    flush()
    return blocks


def _header_start(lines: list[str], label_index: int, floor: int) -> int:
    """Walk back over the doc comment / directives preceding a label."""
    start = label_index
    j = label_index - 1
    while j >= floor:
        raw = lines[j]
        text = raw.strip()
        stripped = strip_comment(raw)
        if not text or text.startswith("//") or text.startswith("/*") \
                or text.startswith("*"):
            start = j
        elif stripped and HEADER_DIRECTIVE_RE.match(stripped):
            start = j
        else:
            break
        j -= 1
    return start


def scan_regions(text: str, path: Path,
                 call_targets: set[str] | None = None) -> list[Region]:
    """Split one source file into callable regions.

    ``call_targets`` is the set of labels reached by ``bl`` anywhere in the
    tree; pass it so that file-local ``bl`` targets become regions in their own
    right. Without it, only ``.global`` symbols are regions.
    """
    call_targets = call_targets or set()
    lines = text.splitlines()
    labels, globals_, _data_lines = _classify_lines(text)
    doc_blocks = _doc_blocks(lines)

    candidates: list[tuple[int, str]] = [
        (i, name) for i, name, is_data in labels
        if not is_data and (name in globals_ or name in call_targets)
    ]
    if not candidates:
        return []

    # Every label that is not a region start still terminates a region when it
    # introduces data (a trailing constant table must not be swallowed into
    # the function above it).
    data_label_starts = sorted(i for i, _n, is_data in labels if is_data)

    def extent(label_index: int, next_index: int | None) -> tuple[int, int]:
        floor = 0
        for other, _n in candidates:
            if other < label_index:
                floor = max(floor, other + 1)
        start = _header_start(lines, label_index, floor)
        end = (_header_start(lines, next_index, label_index + 1)
               if next_index is not None else len(lines))
        for data_index in data_label_starts:
            if label_index < data_index < end:
                end = _header_start(lines, data_index, label_index + 1)
                break
        # A region's own ``ENDFUNC``/``ENDOBJ`` is the author saying where it
        # stops, and it beats every heuristic above. Without this, a file-local
        # helper that merely sits *below* a function is read as living *inside*
        # it: ``detect_cpus`` is a sibling of ``install_sigchld``, not a
        # nested one, but the two are indistinguishable by position alone --
        # ``hex_to_val`` really does sit inside ``decode_url``, whose epilogue
        # is below it. The closing marker tells them apart, and the regions
        # that genuinely nest keep theirs after the helper, so they are
        # unaffected.
        name = next(n for i, n in candidates if i == label_index)
        closer = f"END{{}} {name}"
        for offset in range(label_index + 1, end):
            text = strip_comment(lines[offset])
            if text in (closer.format("FUNC"), closer.format("OBJ")):
                end = offset + 1
                break
        return start, end

    # Tier 1: the top-level units. Every .global symbol is one; so is any bl
    # target that does not sit inside a .global symbol's body (.Lgcm_ghash_run
    # and .Lgcm_gf_mul live in data.S, which exports nothing at all, and
    # p256_reduce sits above the first .global in its file).
    global_indices = [i for i, name in candidates if name in globals_]
    global_extents: list[tuple[int, int]] = []
    for pos, label_index in enumerate(global_indices):
        nxt = global_indices[pos + 1] if pos + 1 < len(global_indices) else None
        global_extents.append((label_index, extent(label_index, nxt)[1]))

    def enclosing_global(label_index: int) -> str | None:
        for start, end in global_extents:
            if start < label_index < end:
                return next(n for i, n in candidates if i == start)
        return None

    top_level = [(i, name) for i, name in candidates
                 if name in globals_ or enclosing_global(i) is None]
    top_set = {i for i, _n in top_level}

    regions: list[Region] = []

    def make(label_index: int, next_index: int | None,
             enclosing: str | None) -> Region:
        start, end = extent(label_index, next_index)
        name = next(n for i, n in candidates if i == label_index)
        doc = "\n".join(raw for raw in lines[start:label_index]
                        if raw.strip().startswith("//"))
        if "Function Name:" not in doc:
            doc = doc_blocks.get(name, doc)
        return Region(
            name=name,
            path=path,
            label_line=label_index + 1,
            start_line=start + 1,
            end_line=end + 1,
            text="\n".join(lines[start:end]),
            body="\n".join(lines[label_index:end]),
            doc=doc,
            is_global=name in globals_,
            is_local_label=name.startswith(".L") or name.startswith("L"),
            enclosing=enclosing,
        )

    # Top-level regions run to the next top-level region, so a nested bl
    # target does not truncate the function it lives inside: decode_url's
    # epilogue sits *below* hex_to_val in the file.
    for pos, (label_index, _name) in enumerate(top_level):
        nxt = top_level[pos + 1][0] if pos + 1 < len(top_level) else None
        regions.append(make(label_index, nxt, None))

    # Tier 2: nested callable regions, each running to the next label that
    # starts a region of either tier.
    for label_index, _name in candidates:
        if label_index in top_set:
            continue
        later = [i for i, _n in candidates if i > label_index]
        nxt = min(later) if later else None
        regions.append(make(label_index, nxt, enclosing_global(label_index)))

    regions.sort(key=lambda r: (r.label_line, r.enclosing is not None))

    # Fallthrough: a region whose last instruction is not a terminator runs on
    # into the next one at the same tier.
    for tier in (None, "nested"):
        same = [r for r in regions
                if (r.enclosing is None) == (tier is None)]
        for idx, region in enumerate(same):
            if idx + 1 >= len(same):
                continue
            insns, _ = parse_instructions(region.body)
            # An empty region is an alias for the label below it -- "_start:"
            # sits directly above "_main:" inside an #ifdef.
            if not insns or not _terminates(insns):
                region.falls_through_to = same[idx + 1].name
    return regions


TERMINATORS = {"ret", "br", "b", "eret"}

SYSCALL_MNEMONICS = {"svc", "SCWISVC"}
EXIT_NUMBER_RE = re.compile(r"\bSYS_exit(?:_group)?\b")


def _terminates(insns: list[Instruction]) -> bool:
    """Does control leave this region for good at its last instruction?

    ``ret``/``b``/``br``/``eret`` are the obvious cases. The exit syscall is
    the non-obvious one: ``worker_shutdown`` and ``sig_tramp`` end in

        SCWINUM SYS_exit
        mov x0, #0
        SCWISVC

    and nothing after that runs. Read as a plain ``svc``, the region looked
    unterminated and was chained into the function textually below it, which
    is where the extra registers those two headers were accused of missing
    (x19-x22, x28, x30 -- ``_main``'s) actually came from. Both headers say so
    in prose; this makes the parser agree.
    """
    last = insns[-1]
    if last.mnemonic in TERMINATORS:
        return True
    if last.mnemonic not in SYSCALL_MNEMONICS:
        return False
    # The syscall number is set a few instructions above the svc, never
    # between it and the argument moves.
    for insn in reversed(insns[-6:]):
        if EXIT_NUMBER_RE.search(insn.text):
            return True
    return False


# ----------------------------------------------------------------------
# Call graph
# ----------------------------------------------------------------------

BL_RE = re.compile(r"^bl\s+([A-Za-z0-9_.$]+)")
B_RE = re.compile(r"^b\s+([A-Za-z_.$][A-Za-z0-9_.$]*)")


def _branch_targets_in(text: str, macros: dict[str, Macro]
                       ) -> tuple[list[str], list[str]]:
    """``(bl targets, b targets)`` in a body, after macro expansion.

    Plain ``b`` matters because several functions are tail-call trampolines --
    ``write_all`` is nothing but ``b transport_write`` -- and their clobber set
    is entirely their target's.
    """
    calls: list[str] = []
    tails: list[str] = []
    for raw in expand_macros(text, macros).splitlines():
        line = strip_comment(raw)
        if not line:
            continue
        while True:
            found = is_label(line)
            if not found:
                break
            line = found[1]
            if not line:
                break
        match = BL_RE.match(line)
        if match:
            calls.append(match.group(1))
            continue
        match = B_RE.match(line)
        if match:
            tails.append(match.group(1))
    return calls, tails


def _call_targets_in(text: str, macros: dict[str, Macro]) -> list[str]:
    return _branch_targets_in(text, macros)[0]


@dataclass
class SourceIndex:
    """Every callable region in the tree, plus who calls whom."""
    regions: list[Region] = field(default_factory=list)
    by_name: dict[str, Region] = field(default_factory=dict)
    # A handful of names (".Lhkdf_memcpy") are defined in more than one file;
    # local labels are file-scope, so keep every definition.
    all_by_name: dict[str, list[Region]] = field(default_factory=dict)
    macros: dict[str, Macro] = field(default_factory=dict)
    # callee name -> list of (caller region name, caller file)
    callers: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    # caller region name -> set of callee names
    calls: dict[str, set[str]] = field(default_factory=dict)
    # caller region name -> set of regions it tail-calls with a plain `b`
    tail_calls: dict[str, set[str]] = field(default_factory=dict)

    # symbol -> files that mention it outside its own definition. A symbol
    # whose address is taken is reachable even with no `bl` to it: the nine
    # h2 frame handlers are reached through the `.quad` jump table in
    # h2_dispatch_frame.S, an edge no textual call graph can follow.
    references: dict[str, set[str]] = field(default_factory=dict)

    def call_sites(self, name: str) -> int:
        return len(self.callers.get(name, []))

    def referenced(self, name: str) -> bool:
        return bool(self.references.get(name))

    def analysis_body(self, region: Region, _depth: int = 3) -> str:
        """The region body, with any fallthrough successor appended.

        ``p256_fe_sqr`` ends in ``mov x2, x1`` and runs straight on into
        ``p256_fe_mul``; analysing it without the successor would report a
        two-instruction function with no ``ret``.
        """
        body = region.body
        seen = {region.name}
        current = region
        while current.falls_through_to and _depth > 0:
            nxt = self.by_name.get(current.falls_through_to)
            if nxt is None or nxt.name in seen:
                break
            body += "\n" + nxt.body
            seen.add(nxt.name)
            current = nxt
            _depth -= 1
        return body


def index_source(root: Path | None = None, *,
                 linux: bool | None = None) -> SourceIndex:
    """Scan ``src/`` and build the region list and call graph."""
    root = root or ROOT
    macros = load_macros(root, linux=linux)
    paths = [p for p in sorted((root / "src").rglob("*.S"))
             if p.name not in SKIP_FILES]
    texts = {p: p.read_text(errors="replace") for p in paths}

    # Pass 1: every label reached by bl, anywhere.
    call_targets: set[str] = set()
    for text in texts.values():
        call_targets.update(_call_targets_in(text, macros))

    # Doc headers, keyed by the name they declare. The x25519 sources chain
    # through #include and each file carries the header for the function
    # *defined in the next file*, so this lookup has to be tree-wide.
    doc_blocks: dict[str, str] = {}
    for text in texts.values():
        for name, block in _doc_blocks(text.splitlines()).items():
            doc_blocks.setdefault(name, block)

    # Pass 2: regions, now that local bl targets are known to be callable.
    index = SourceIndex(macros=macros)
    for path, text in texts.items():
        for region in scan_regions(text, path, call_targets):
            if "Clobbered Registers:" not in region.doc:
                region.doc = doc_blocks.get(region.name, region.doc)
            index.regions.append(region)
            index.by_name.setdefault(region.name, region)
            index.all_by_name.setdefault(region.name, []).append(region)

    # Pass 3: call edges, attributed to the enclosing region.
    known = set(index.by_name)
    # Which region owns each label, per file. A tail branch does not have to
    # name a region: `child` ends in `b Lchild_common`, a plain label in the
    # middle of `child_with_data`'s body, and `h2_stage_headers` ends in
    # `b .Lh2wh_entry` the same way. Those are still tail calls into another
    # function -- the branch target just is not the function's entry -- so the
    # owning region supplies the edge. Labels are file-scope, so this map is
    # too; where a nested region and its enclosing one both contain the label,
    # the innermost (last, by sort order) owner wins.
    label_owner: dict[tuple[Path, str], str] = {}
    for region in index.regions:
        for label in parse_instructions(region.body)[1]:
            label_owner[(region.path, label)] = region.name

    for region in index.regions:
        calls, tails = _branch_targets_in(region.body, macros)
        callees = set(calls)
        index.calls[region.name] = callees
        # Only inter-region `b`s are tail calls; a `b` to a label inside this
        # region is ordinary control flow.
        local_labels = set(parse_instructions(region.body)[1])
        resolved: set[str] = set()
        for target in tails:
            if target in local_labels or target == region.name:
                continue
            if target in known:
                resolved.add(target)
                continue
            owner = label_owner.get((region.path, target))
            if owner is not None and owner != region.name:
                resolved.add(owner)
        index.tail_calls[region.name] = resolved
        for callee in callees:
            index.callers.setdefault(callee, []).append(
                (region.name, region.rel))
        for callee in index.tail_calls[region.name]:
            index.callers.setdefault(callee, []).append(
                (region.name, region.rel))

    # Pass 4: address-taken references, so a symbol reached only through a
    # jump table is not mistaken for dead code.
    word_res = {name: re.compile(r"\b" + re.escape(name) + r"\b")
                for name in index.by_name}
    for path, text in texts.items():
        for raw in text.splitlines():
            line = strip_comment(raw)
            if not line:
                continue
            # A label definition, a visibility directive, or a branch is not
            # an address-taken reference: the first two declare the symbol and
            # the third is already an edge in the call graph.
            while True:
                found = is_label(line)
                if not found:
                    break
                line = found[1]
                if not line:
                    break
            if not line or DIRECTIVE_RE.match(line):
                if not line or not DATA_DIRECTIVE_RE.match(line):
                    continue
            if re.match(r"^(bl|blr|b|b\.\w+|bc\.\w+)\s", line):
                continue
            for name, pattern in word_res.items():
                if pattern.search(line):
                    index.references.setdefault(name, set()).add(str(path))
    return index


# ----------------------------------------------------------------------
# Self-test
# ----------------------------------------------------------------------

def self_test() -> int:
    """Assert the index actually sees the repository.

    This exists because the failure it guards against was *silent*. Region
    discovery ran over raw lines and did not understand ``FUNC``/``OBJECT``,
    the macro form src/ declares every symbol with, so the index held only
    the couple of dozen ``.L`` labels that some ``bl`` names directly. Nothing
    crashed. ``abi.py`` answered "function not found" one function at a time,
    ``regpressure.py`` ranked the same handful, and ``validate_clobbers.py``
    reported "headers checked: 12" as though twelve were all there were --
    three green gates checking almost nothing, for as long as nobody counted.

    So the assertions here are about *coverage*, not correctness: a parser
    that silently sees less than the repository contains is the specific way
    this tooling fails.
    """
    index = index_source()
    failures: list[str] = []

    exported = sorted(n for n in index.all_by_name if not n.startswith("."))
    sources = [p for p in sorted((ROOT / "src").rglob("*.S"))
               if p.name not in SKIP_FILES]
    declared = 0
    for path in sources:
        for raw in path.read_text(errors="replace").splitlines():
            if symbol_macro(strip_comment(raw)):
                declared += 1
    # OBJECT declares data, which is correctly not a region, so the index is
    # expected to hold fewer symbols than the macros declare -- but not an
    # order of magnitude fewer.
    if len(exported) < declared // 2:
        failures.append(
            f"only {len(exported)} exported regions for {declared} "
            f"FUNC/OBJECT declarations -- region discovery is not seeing "
            f"the tree")

    # A spread across subsystems, each declared with FUNC and each reached
    # differently, so a regression in one path does not hide behind another.
    for name in ("h2_stream_find", "h2_process_request", "p256_reduce",
                 "memcpy", "aes_gcm_encrypt"):
        if name not in index.all_by_name:
            failures.append(f"{name} missing from the index")

    # OBJECT symbols are data and must stay out of the callable regions.
    for name in ("h2_streams", "h2_stream_ids"):
        if name in index.all_by_name:
            failures.append(f"{name} is data but was indexed as a region")

    for line in failures:
        print(f"FAIL: {line}")
    if failures:
        return 1
    print(f"OK: {len(exported)} exported regions from {declared} "
          f"FUNC/OBJECT declarations")
    return 0


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true",
                        help="assert the index sees the repository")
    args = parser.parse_args()
    if args.self_test:
        raise SystemExit(self_test())
    parser.print_help()
