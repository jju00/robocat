"""
Tools: source snippet reader
============================
• mcp__nld__read_source_context
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional, Any

from mcp.server.fastmcp import FastMCP


# ─────────────────────────────────────────────────────────────
# util
# ─────────────────────────────────────────────────────────────

def _json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


def _resolve_file(file_path: str) -> Path:
    p = Path(file_path)

    # 1. 그대로 존재
    if p.exists():
        return p.resolve()

    workspace_roots = (
        Path("/home/zerovirus/workspace/lighttpd1.4"),
        Path("/home/zerovirus/workspace/lighttpd/source"),
        Path.cwd(),
    )

    # 2. CPG 경로 (/app/source → host 변환)
    if file_path.startswith("/app/source"):
        relative = file_path.replace("/app/source", "").lstrip("/")
        for root in workspace_roots:
            candidate = root / relative
            if candidate.exists():
                return candidate.resolve()

    # 3. 상대 경로 fallback
    for root in workspace_roots:
        candidate = root / file_path
        if candidate.exists():
            return candidate.resolve()

    raise FileNotFoundError(f"file not found: {file_path}")


def _extract_lines(text: str, start: int, end: int) -> str:
    lines = text.splitlines()
    return "\n".join(lines[max(0, start-1):min(len(lines), end)])


# ─────────────────────────────────────────────────────────────
# Tool 1: read_source_context
# ─────────────────────────────────────────────────────────────

def mcp__nld__read_source_context(
    file_path: str,
    line: Optional[int] = None,
    before: int = 30,
    after: int = 30,
    function_name: Optional[str] = None,
) -> str:
    """
    필요한 코드 snippet만 읽기 (전체 파일 금지)

    - function_name → 함수 전체 추출
    - line → 주변 snippet
    """

    try:
        path = _resolve_file(file_path)
    except Exception as e:
        return _json({"error": str(e)})

    text = path.read_text(errors="ignore")
    normalized_line: Optional[int] = None
    if line is not None:
        try:
            normalized_line = int(line)
        except (TypeError, ValueError):
            return _json({"error": f"invalid line: {line}"})

    # 1. function 기준
    if function_name:
        pattern = re.compile(rf"\b{re.escape(function_name)}\b\s*\(")

        lines = text.splitlines()

        for i, l in enumerate(lines):
            if pattern.search(l):
                start = i
                brace = 0
                started = False

                for j in range(i, len(lines)):
                    brace += lines[j].count("{")
                    if "{" in lines[j]:
                        started = True
                    brace -= lines[j].count("}")

                    if started and brace <= 0:
                        end = j
                        return _json({
                            "file_path": file_path,
                            "start_line": start+1,
                            "end_line": end+1,
                            "code": "\n".join(lines[start:end+1])
                        })

        return _json({
            "error": f"function not found: {function_name}",
            "file_path": file_path
        })

    # 2. line 기준
    if normalized_line is None:
        return _json({"error": "line or function_name required"})

    start = max(1, normalized_line - before)
    end = normalized_line + after

    snippet = _extract_lines(text, start, end)

    return _json({
        "file_path": file_path,
        "start_line": start,
        "end_line": end,
        "code": snippet
    })


# ─────────────────────────────────────────────────────────────
# register
# ─────────────────────────────────────────────────────────────

def register(mcp: FastMCP) -> None:
    mcp.tool()(mcp__nld__read_source_context)
