#!/usr/bin/env python3
"""Quick test driver for the mutation transforms during development."""

import sys
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mutations import apply_mutations  # noqa: E402

source = Path(sys.argv[1]).read_text()
pattern = re.compile(
    r"(?ms)^[ \t]*\.global[ \t]+memcpy.*?(?=^[ \t]*\.global[ \t]+|\Z)"
)
match = pattern.search(source)
function_text = match.group(0)

candidates = apply_mutations(function_text)
print(f"mutations produced: {len(candidates)}")
for cand in candidates:
    print(f"\n===== {cand.name} =====")
    print(cand.source)
