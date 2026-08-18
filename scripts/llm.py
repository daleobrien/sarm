#!/usr/bin/env python3
"""LLM backend for the optimization harness.

The optimizer never cares *which* model answers: everything behind the
:class:`LLM` interface (OPTIMISATION.MD, "Local LLM"). Two backends are
provided:

* ``ollama-http`` -- talks to a local Ollama server's ``/api/generate``
  endpoint (``http://localhost:11434`` by default), which is the setup the
  doc recommends for a 36 GB RAM machine (small/medium coding model +
  tight feedback loop + many iterations).
* ``command`` -- invokes an arbitrary CLI (``--llm "ollama run
  qwen3.5-coder"``) with the prompt as the final argument, mirroring the
  original prototype in OPTIMISATION.MD.

Both backends ask the model for strict JSON (``{"explanation": ...,
"assembly": ...}``) and parse it tolerantly so a chatty model still works.
"""

from __future__ import annotations

import json
import re
import shutil
import urllib.request
from dataclasses import dataclass, field

from common import Result, run_command


class LLMError(Exception):
    """Raised when the LLM backend cannot be used at all."""


@dataclass
class LLMCandidate:
    """One parsed proposal from the model."""

    assembly: str
    explanation: str = ""
    raw: str = ""


def _extract_json(text: str) -> dict | None:
    """Best-effort JSON object extraction from model output.

    Tries a strict parse first, then scans for the first balanced ``{...}``
    block (models love to wrap JSON in prose or fences).
    """
    text = text.strip()
    # Strip markdown fences around a JSON block.
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()

    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        pass

    # Balanced-brace scan.
    start = text.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escape = False
        for i in range(start, len(text)):
            ch = text[i]
            if in_string:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : i + 1])
                    except json.JSONDecodeError:
                        break
        start = text.find("{", start + 1)
    return None


class LLM:
    """A small interface hiding which local model does the reasoning."""

    def __init__(
        self,
        backend: str = "ollama-http",
        model: str = "qwen2.5-coder:7b",
        url: str = "http://localhost:11434",
        command: list[str] | None = None,
        timeout: int = 900,
    ) -> None:
        self.backend = backend
        self.model = model
        self.url = url.rstrip("/")
        self.command = command or ["ollama", "run", model]
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    def available(self) -> bool:
        if self.backend == "command":
            return shutil.which(self.command[0]) is not None
        # ollama-http: is the server reachable?
        try:
            with urllib.request.urlopen(
                self.url + "/api/tags", timeout=3
            ) as resp:
                return resp.status == 200
        except OSError:
            return False

    # ------------------------------------------------------------------
    # Generation
    # ------------------------------------------------------------------

    def generate(self, prompt: str, n: int = 1) -> list[LLMCandidate] | None:
        """Request ``n`` independent candidates.

        Each request asks for a single JSON object; ``n`` independent
        requests give genuinely independent proposals (the "multiple LLM
        candidates" idea from the doc).
        """
        if self.backend == "ollama-http":
            return self._generate_http(prompt, n)
        return self._generate_command(prompt, n)

    # -- ollama HTTP ---------------------------------------------------

    def _generate_http(self, prompt: str, n: int) -> list[LLMCandidate] | None:
        results: list[LLMCandidate] = []
        for _ in range(n):
            body = json.dumps(
                {
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0.7},
                }
            ).encode()
            request = urllib.request.Request(
                self.url + "/api/generate",
                data=body,
                headers={"Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                    payload = json.loads(resp.read().decode())
            except (OSError, json.JSONDecodeError) as exc:
                print(f"  ✗ LLM request failed: {exc}")
                return None

            candidate = self._parse(payload.get("response", ""))
            if candidate is None:
                print("  ✗ LLM returned unparseable output")
                return None
            results.append(candidate)
        return results

    # -- generic command backend --------------------------------------

    def _generate_command(self, prompt: str, n: int) -> list[LLMCandidate] | None:
        results: list[LLMCandidate] = []
        for _ in range(n):
            result = run_command(self.command + [prompt], timeout=self.timeout)
            if not result.success:
                print(f"  ✗ LLM failed:\n{result.summary()}")
                return None
            candidate = self._parse(result.output)
            if candidate is None:
                print("  ✗ LLM returned unparseable output")
                print(result.output[:2000])
                return None
            results.append(candidate)
        return results

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse(text: str) -> LLMCandidate | None:
        data = _extract_json(text)
        if data is None:
            # No JSON at all: treat the whole response as assembly text.
            assembly = text.strip()
            if not assembly:
                return None
            return LLMCandidate(assembly=assembly, raw=text)

        assembly = str(data.get("assembly", "")).strip()
        if not assembly:
            return None
        return LLMCandidate(
            assembly=assembly,
            explanation=str(data.get("explanation", "")).strip(),
            raw=text,
        )


# Convenience alias so `from llm import LLMCandidate` reads naturally.
__all__ = ["LLM", "LLMCandidate", "LLMError"]
