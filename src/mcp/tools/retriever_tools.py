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
_cache_loaded: bool = False


def load_retriever_cache() -> None:
    """retriever_output.json을 메모리에 로드하고 id / function 기준 인덱스 생성."""
    global _retriever_by_id, _retriever_by_function, _cache_loaded

    _retriever_by_id = {}
    _retriever_by_function = {}
    _cache_loaded = False

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

    _cache_loaded = True
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
    diff_functions.json의 함수 각각마다 코드적으로 유사한 함수를 매핑, 그 함수들에서 나왔던 기존 cve지식 중 가장 유사한 결과를 top_k개 반환한다.
    
    representative_pattern 중심으로 취약점 유형을 추론하되, 맹신하지 말고 단순히 참고자료로만 사용한다.

    sample_id 또는 function_name 중 하나를 반드시 지정해야 한다.

    Args:
        sample_id:     retriever_output_top1.json 의 id 필드 (예: 1, 2, 3 ...).
                       diff_functions.json > files[].functions[].id 와 동일한 값이며,
                       분석 대상 함수를 식별하는 1-based 순번이다.
        function_name: 분석 대상 함수 이름 (정확 일치 우선, 없으면 부분 일치).
                       diff_retriever.json 의 function 필드 기준으로 조회한다.
        top_k:         반환할 최대 취약점 항목 수 (기본: 3)

    Returns:
        JSON 문자열. 주요 필드:
          id                   : 샘플 식별자
          function             : 함수 이름
          file_path            : 파일 경로
          top_vulnerabilities  : 취약점 항목 리스트 (top_k 개)
            name                          : 취약점 유형 (예: "Buffer Overflow")
            reason                        : 해당 취약점으로 판단한 근거
            supporting_cve_ids            : 근거 CVE ID 목록
            representative_pattern        : 취약 패턴 요약 설명
            memory_corruption_category    : 메모리 손상 세부 분류 (없으면 null)
            cwe_ids                       : 관련 CWE ID 목록
            representative_code_examples  : 취약 코드 예시 목록
            common_indicators             : 취약 패턴 식별 지표 목록
    """
    # 서버가 import 방식으로 올라와 __main__ 블록이 실행되지 않아도 동작하도록
    # 첫 호출 시 캐시를 지연 로드한다.
    if not _cache_loaded:
        load_retriever_cache()

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

    top_vulns = entry.get("top_vulnerabilities", [])[:top_k]

    result = {
        "sample_id":          entry.get("id"),
        "function":           entry.get("function", ""),
        "file_path":          entry.get("file_path", ""),
        "project":            entry.get("project", ""),
        "purpose":            entry.get("purpose", ""),
        "function_summary":   entry.get("function_summary", ""),
        "top_vulnerabilities": top_vulns,
    }
    return json.dumps(result, ensure_ascii=False, indent=2)


def register(mcp: FastMCP) -> None:
    """tool 등록 — server.py 에서 mcp 인스턴스를 받아 호출."""
    if not _cache_loaded:
        load_retriever_cache()
    mcp.tool()(get_retrieved_knowledge)
