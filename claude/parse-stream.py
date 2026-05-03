#!/usr/bin/env python3
"""Extract a JSON verdict / findings object from a Claude stream-json log.

Multi-strategy extractor:
  1. Reconstruct the agent's final response by concatenating every `text`
     block inside `assistant` events.
  2. Try direct JSON parse of the whole reconstructed text.
  3. Try fenced code blocks (```json {...} ``` or ``` {...} ```).
  4. Walk the text and collect every balanced `{...}` block that parses
     as JSON, then pick the last one containing the required key.
  5. Fall back to writing the raw text (downstream parser will mark it
     MALFORMED and the user can inspect).

Usage:
  parse-stream.py <jsonl-path> [require-key]
    require-key defaults to no requirement; pass "status" for exploiter
    and "findings" for hunter / surveyor "findings"-style outputs.
"""
from __future__ import annotations

import json
import re
import sys


def collect_text(jsonl_path: str) -> str:
    parts: list[str] = []
    with open(jsonl_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("type") != "assistant":
                continue
            msg = ev.get("message", {}) or {}
            for block in msg.get("content", []) or []:
                if isinstance(block, dict) and block.get("type") == "text":
                    t = block.get("text", "")
                    if isinstance(t, str):
                        parts.append(t)
    return "\n".join(parts).strip()


def find_balanced_jsons(text: str) -> list[str]:
    """Return every balanced `{...}` block that parses as a JSON object."""
    out: list[str] = []
    n = len(text)
    i = 0
    while i < n:
        if text[i] == "{":
            depth = 0
            j = i
            in_str = False
            esc = False
            while j < n:
                c = text[j]
                if in_str:
                    if esc:
                        esc = False
                    elif c == "\\":
                        esc = True
                    elif c == '"':
                        in_str = False
                else:
                    if c == '"':
                        in_str = True
                    elif c == "{":
                        depth += 1
                    elif c == "}":
                        depth -= 1
                        if depth == 0:
                            blob = text[i : j + 1]
                            try:
                                json.loads(blob)
                                out.append(blob)
                            except json.JSONDecodeError:
                                pass
                            i = j
                            break
                j += 1
        i += 1
    return out


VERDICT_STATUSES = {"CONFIRMED", "FAILED", "UNCLEAR"}


def matches_shape(parsed: object, want_key: str | None) -> bool:
    """Heuristic: does this dict look like the verdict / findings object we want?"""
    if not isinstance(parsed, dict):
        return False
    if want_key is None:
        return True
    if want_key not in parsed:
        return False
    if want_key == "status":
        # Only accept the verdict status values, not random HTTP statuses.
        s = parsed.get("status")
        if not isinstance(s, str):
            return False
        return s.upper() in VERDICT_STATUSES
    if want_key == "findings":
        return isinstance(parsed.get("findings"), list)
    return True


def extract(text: str, want_key: str | None) -> str:
    text = text.strip()
    if not text:
        return ""

    # 1. Direct parse of the whole thing
    try:
        parsed = json.loads(text)
        if matches_shape(parsed, want_key):
            return text
    except json.JSONDecodeError:
        pass

    # 2. Fenced code blocks (largest first — more likely to be the full verdict)
    fenced = list(re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL))
    for m in sorted(fenced, key=lambda m: -len(m.group(1))):
        blob = m.group(1)
        try:
            parsed = json.loads(blob)
            if matches_shape(parsed, want_key):
                return blob
        except json.JSONDecodeError:
            continue

    # 3. Every balanced {...}; pick the last one whose shape matches
    blobs = find_balanced_jsons(text)
    for b in reversed(blobs):
        try:
            parsed = json.loads(b)
            if matches_shape(parsed, want_key):
                return b
        except json.JSONDecodeError:
            continue
    # If nothing shape-matched, fall back to the largest blob (likely the
    # closest thing to a verdict shape the agent produced).
    if blobs:
        return max(blobs, key=len)

    # 4. fallback: raw text (caller will mark it MALFORMED)
    return text


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: parse-stream.py <jsonl-path> [require-key]", file=sys.stderr)
        return 2
    jsonl_path = sys.argv[1]
    want_key = sys.argv[2] if len(sys.argv) > 2 else None
    text = collect_text(jsonl_path)
    out = extract(text, want_key)
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
