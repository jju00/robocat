"""Tool 1: get_retrieved_knowledge
================================
사전 계산된 retriever 결과(CVE 취약점 지식) 조회 tool 및 in-memory 캐시.
"""

from __future__ import annotations

import json
import sys
from typing import Optional

from mcp.server.fastmcp import FastMCP

from src.mcp.config import DIFF_RETRIEVER_PATH, RETRIEVER_OUTPUT_PATH

# ──────────────────────────────────────────────────────────────────────────────
# In-memory 인덱스 (서버 기동 시 load_retriever_cache() 로 채움)
# ──────────────────────────────────────────────────────────────────────────────

_retriever_by_id:       dict[int, dict] = {}   # id → RetrieverResultDTO
_retriever_by_function: dict[str, dict] = {}   # function_name → RetrieverResultDTO


def load_retriever_cache() -> None:
    """retriever_output.json을 메모리에 로드하고 id / function 기준 인덱스 생성."""
    global _retriever_by_id, _retriever_by_function

    if not RETRIEVER_OUTPUT_PATH.exists():
        print(
            f"[NLD-MCP] WARNING: retriever output not found at {RETRIEVER_OUTPUT_PATH}",
            file=sys.stderr,
        )
        return

    with open(RETRIEVER_OUTPUT_PATH, "r", encoding="utf-8") as f:
        data: list[dict] = json.load(f)

    for item in data:
        item_id = item.get("id")
        if item_id is not None:
            _retriever_by_id[int(item_id)] = item

    # diff_retriever.json 에는 function 이름이 있으므로 id → function 매핑 보조
    if DIFF_RETRIEVER_PATH.exists():
        with open(DIFF_RETRIEVER_PATH, "r", encoding="utf-8") as f:
            diff_data: list[dict] = json.load(f)

        # diff_retriever 는 순서가 retriever_output.json 과 일치한다고 가정 (동일 인덱싱)
        for idx, diff_item in enumerate(diff_data, start=1):
            func_name = diff_item.get("function", "")
            if func_name and idx in _retriever_by_id:
                entry = _retriever_by_id[idx].copy()
                entry["function"]         = func_name
                entry["file_path"]        = diff_item.get("file_path", "")
                entry["project"]          = diff_item.get("project", "")
                entry["purpose"]          = diff_item.get("purpose", "")
                entry["function_summary"] = diff_item.get("function_summary", "")
                _retriever_by_id[idx]             = entry
                _retriever_by_function[func_name] = entry

    print(f"[NLD-MCP] Loaded {len(_retriever_by_id)} retriever entries.", file=sys.stderr)


# ──────────────────────────────────────────────────────────────────────────────
# Tool 정의
# ──────────────────────────────────────────────────────────────────────────────

def get_retrieved_knowledge(
    sample_id: Optional[int] = None,
    function_name: Optional[str] = None,
    top_k: int = 3,
) -> str:
    """
    사전 계산된 retriever 결과(CVE 취약점 지식)를 반환한다.

    sample_id 또는 function_name 중 하나를 반드시 지정해야 한다.

    Args:
        sample_id:     retriever_output.json 의 id 필드 (예: 1, 2, 3 ...)
        function_name: 분석 대상 함수의 fully qualified name
                       (예: "Advisor::evaluateRuleExpression")
        top_k:         반환할 최대 CVE 지식 항목 수 (기본: 3)

    Returns:
        JSON 문자열. 각 항목에 cve_id, vulnerability_behavior, solution_behavior 포함.
    """
    entry: Optional[dict] = None
    if sample_id is not None:
        entry = _retriever_by_id.get(int(sample_id))
    elif function_name:
        # 정확히 일치하는 경우 우선, 없으면 부분 일치 탐색
        entry = _retriever_by_function.get(function_name)
        if entry is None:
            for fn, e in _retriever_by_function.items():
                if function_name.lower() in fn.lower():
                    entry = e
                    break

    if entry is None:
        return json.dumps(
            {
                "error": (
                    f"retriever 결과를 찾을 수 없습니다. "
                    f"(sample_id={sample_id}, function={function_name})"
                )
            },
            ensure_ascii=False,
            indent=2,
        )

    knowledge_list = entry.get("retrieved_knowledge", [])[:top_k]

    result = {
        "sample_id":           entry.get("id"),
        "function":            entry.get("function", ""),
        "file_path":           entry.get("file_path", ""),
        "project":             entry.get("project", ""),
        "purpose":             entry.get("purpose", ""),
        "function_summary":    entry.get("function_summary", ""),
        "retrieved_knowledge": knowledge_list,
    }
    return json.dumps(result, ensure_ascii=False, indent=2)


def register(mcp: FastMCP) -> None:
    """tool 등록 — server.py 에서 mcp 인스턴스를 받아 호출."""
    mcp.tool()(get_retrieved_knowledge)
