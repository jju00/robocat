"""
NLD MCP Server
==============
Codex CLI 가 취약점 판단 시 호출하는 MCP tool server.

실행 방법:
    python -m src.mcp.server          # stdio transport (Codex CLI 연결용)
    python src/mcp/server.py          # 직접 실행 (동일)

Codex CLI 연결 설정 (~/.codex/config.toml 또는 codex 실행 플래그):
    [[mcp_servers]]
    name = "nld"
    command = ["python", "src/mcp/server.py"]
    transport = "stdio"

Tools:
  1. get_retrieved_knowledge   - 사전 계산된 retriever 결과 조회
  2. get_cpg_summary           - Joern CPG 전체 요약 (call chain, params, reachable sinks)
  3. find_dataflow             - source → sink 데이터흐름 경로 추적
  4. find_sanitizer_or_guard   - sanitizer / guard / validation 코드 존재 여부 확인

환경변수:
    RETRIEVER_OUTPUT_PATH   retriever 결과 JSON 경로 (기본: data/retriever/retriever_output.json)
    JOERN_HOST              Joern REST server host (기본: localhost)
    JOERN_PORT              Joern REST server port (기본: 8080)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

import httpx
from mcp.server.fastmcp import FastMCP

# ──────────────────────────────────────────────────────────────────────────────
# 경로 설정
# ──────────────────────────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parents[2]   # src/mcp/server.py → NLD/

RETRIEVER_OUTPUT_PATH = Path(
    os.getenv("RETRIEVER_OUTPUT_PATH", str(_ROOT / "data" / "retriever" / "retriever_output.json"))
)
DIFF_RETRIEVER_PATH = Path(
    os.getenv("DIFF_RETRIEVER_PATH", str(_ROOT / "data" / "diff" / "diff_retriever.json"))
)

JOERN_HOST = os.getenv("JOERN_HOST", "localhost")
JOERN_PORT = int(os.getenv("JOERN_PORT", "8080"))
JOERN_BASE_URL = f"http://{JOERN_HOST}:{JOERN_PORT}"

# ──────────────────────────────────────────────────────────────────────────────
# 전역 캐시 (서버 기동 시 1회 로드)
# ──────────────────────────────────────────────────────────────────────────────
_retriever_by_id:       dict[int, dict]  = {}   # id → RetrieverResultDTO
_retriever_by_function: dict[str, dict]  = {}   # function_name → RetrieverResultDTO


def _load_retriever_cache() -> None:
    """retriever_output.json을 메모리에 로드하고 id / function 기준 인덱스 생성."""
    global _retriever_by_id, _retriever_by_function

    if not RETRIEVER_OUTPUT_PATH.exists():
        print(f"[NLD-MCP] WARNING: retriever output not found at {RETRIEVER_OUTPUT_PATH}", file=sys.stderr)
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
                entry["function"]     = func_name
                entry["file_path"]    = diff_item.get("file_path", "")
                entry["project"]      = diff_item.get("project", "")
                entry["purpose"]      = diff_item.get("purpose", "")
                entry["function_summary"] = diff_item.get("function_summary", "")
                _retriever_by_id[idx]           = entry
                _retriever_by_function[func_name] = entry

    print(f"[NLD-MCP] Loaded {len(_retriever_by_id)} retriever entries.", file=sys.stderr)


# ──────────────────────────────────────────────────────────────────────────────
# Joern REST 헬퍼
# ──────────────────────────────────────────────────────────────────────────────
def _joern_query(cpgql: str, timeout: int = 30) -> dict[str, Any]:
    """
    Joern REST server 에 CPGQL 쿼리를 전송하고 응답을 반환한다.

    Joern 서버 시작:
        joern --server               # 기본 포트 8080

    반환 예시:
        {"success": true, "stdout": "...", "stderr": ""}
    """
    url = f"{JOERN_BASE_URL}/v1/query"
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.post(url, json={"query": cpgql})
            response.raise_for_status()
            return response.json()
    except httpx.ConnectError:
        return {
            "success": False,
            "error": f"Joern REST server 에 연결할 수 없습니다. ({JOERN_BASE_URL})\n"
                     "joern --server 명령으로 서버를 먼저 시작하세요.",
            "stdout": "",
            "stderr": "",
        }
    except Exception as exc:
        return {
            "success": False,
            "error": str(exc),
            "stdout": "",
            "stderr": "",
        }


def _fmt_joern(raw: dict[str, Any]) -> str:
    """Joern 응답을 Codex 가 읽기 좋은 문자열로 정규화."""
    if not raw.get("success"):
        err = raw.get("error") or raw.get("stderr") or "Unknown Joern error"
        return f"[Joern ERROR] {err}"
    out = raw.get("stdout", "").strip()
    return out if out else "(no results)"


# ──────────────────────────────────────────────────────────────────────────────
# FastMCP 서버 인스턴스
# ──────────────────────────────────────────────────────────────────────────────
mcp = FastMCP(
    name="nld-vulnerability-analysis",
    instructions=(
        "NLD 취약점 탐지 파이프라인의 MCP server입니다.\n"
        "사용 가능한 tool:\n"
        "  1. get_retrieved_knowledge   - 사전 계산된 CVE 지식 조회\n"
        "  2. get_cpg_summary           - Joern CPG 요약 (call chain, params, sinks)\n"
        "  3. find_dataflow             - source → sink 데이터흐름 경로\n"
        "  4. find_sanitizer_or_guard   - sanitizer / validation / guard 존재 여부\n\n"
        "취약점 판단 순서 권장:\n"
        "  1. get_retrieved_knowledge 로 관련 CVE 지식 확인\n"
        "  2. get_cpg_summary 로 함수 구조/호출 흐름 파악\n"
        "  3. find_dataflow 로 user input → sink 경로 존재 여부 확인\n"
        "  4. find_sanitizer_or_guard 로 방어 코드 존재 여부 확인\n"
        "  5. 1~4 결과를 종합하여 취약(YES) / 안전(NO) / 불확실(-1) 판정"
    ),
)


# ──────────────────────────────────────────────────────────────────────────────
# Tool 1: get_retrieved_knowledge
# ──────────────────────────────────────────────────────────────────────────────
@mcp.tool()
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
    # 조회
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
            {"error": f"retriever 결과를 찾을 수 없습니다. (sample_id={sample_id}, function={function_name})"},
            ensure_ascii=False,
            indent=2,
        )

    knowledge_list = entry.get("retrieved_knowledge", [])[:top_k]

    result = {
        "sample_id":        entry.get("id"),
        "function":         entry.get("function", ""),
        "file_path":        entry.get("file_path", ""),
        "project":          entry.get("project", ""),
        "purpose":          entry.get("purpose", ""),
        "function_summary": entry.get("function_summary", ""),
        "retrieved_knowledge": knowledge_list,
    }
    return json.dumps(result, ensure_ascii=False, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# Tool 2: get_cpg_summary
# ──────────────────────────────────────────────────────────────────────────────
@mcp.tool()
def get_cpg_summary(
    file_path: str,
    function_name: str,
) -> str:
    """
    Joern CPG(Code Property Graph) 에서 대상 함수의 구조/호출 흐름 요약을 반환한다.

    포함 정보:
      - 함수 시그니처 (파라미터 이름/타입)
      - 직접 호출하는 함수 목록 (callees)
      - 이 함수를 호출하는 함수 목록 (callers)
      - 함수 내 식별된 잠재적 sink 호출 목록

    Args:
        file_path:     CPG 에 로드된 프로젝트 내 파일 경로
                       (예: "libraries/classes/Advisor.php")
        function_name: 분석할 함수 이름 (예: "evaluateRuleExpression")

    Returns:
        JSON 문자열 with keys: signature, parameters, callees, callers, potential_sinks
    """
    # 함수 파라미터
    q_params = (
        f'cpg.method.filename("{file_path}").name("{function_name}")'
        f'.parameter.map(p => s"${{p.order}}: ${{p.name}} [${{p.typeFullName}}]").l'
    )
    # callees (호출하는 함수)
    q_callees = (
        f'cpg.method.filename("{file_path}").name("{function_name}")'
        f'.callee.name.dedup.l'
    )
    # callers (호출하는 함수)
    q_callers = (
        f'cpg.method.filename("{file_path}").name("{function_name}")'
        f'.caller.name.dedup.l'
    )
    # potential sinks: eval, exec, include, require, system, unserialize 등
    SINK_NAMES = [
        "eval", "exec", "system", "passthru", "shell_exec",
        "include", "require", "unserialize", "call_user_func",
        "preg_replace", "assert",
    ]
    sink_filter = "|".join(SINK_NAMES)
    q_sinks = (
        f'cpg.method.filename("{file_path}").name("{function_name}")'
        f'.call.name("({sink_filter})").map(c => s"${{c.name}} @ line ${{c.lineNumber}}").l'
    )

    params_raw   = _joern_query(q_params)
    callees_raw  = _joern_query(q_callees)
    callers_raw  = _joern_query(q_callers)
    sinks_raw    = _joern_query(q_sinks)

    result = {
        "file_path":       file_path,
        "function":        function_name,
        "parameters":      _fmt_joern(params_raw),
        "callees":         _fmt_joern(callees_raw),
        "callers":         _fmt_joern(callers_raw),
        "potential_sinks": _fmt_joern(sinks_raw),
    }
    return json.dumps(result, ensure_ascii=False, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# Tool 3: find_dataflow
# ──────────────────────────────────────────────────────────────────────────────
@mcp.tool()
def find_dataflow(
    file_path: str,
    function_name: str,
    sink_kind: str = "eval",
) -> str:
    """
    Joern taint analysis 를 사용하여 user input(source) → sink 데이터흐름 경로를 반환한다.

    Args:
        file_path:     CPG 에 로드된 파일 경로
        function_name: 분석할 함수 이름
        sink_kind:     추적할 sink 함수 이름 (기본: "eval")
                       가능한 값 예시: "eval", "exec", "include", "unserialize",
                                       "preg_replace", "call_user_func", "system"

    Returns:
        JSON 문자열 with keys:
          - sink_kind: 추적한 sink
          - paths_found: 발견된 경로 수
          - paths: 경로 요약 목록 (각 항목은 source → ... → sink 형태 문자열)
          - raw_output: Joern 원본 출력
    """
    # source: HTTP 요청 파라미터 계열 식별자 ($_ 변수, 파라미터 등)
    # Joern taint tracking (CPGQL dataflow API)
    q_dataflow = (
        f'val src = cpg.method.filename("{file_path}").name("{function_name}")'
        f'.parameter.l\n'
        f'val sink = cpg.call.name("{sink_kind}").l\n'
        f'sink.reachableByFlows(src).p'
    )

    raw = _joern_query(q_dataflow)
    output = _fmt_joern(raw)

    # 경로 수 추정 (줄 수 기반 휴리스틱)
    lines = [l for l in output.splitlines() if l.strip()]
    paths_found = sum(1 for l in lines if "→" in l or "Flow" in l or "Parameter" in l)

    result = {
        "file_path":    file_path,
        "function":     function_name,
        "sink_kind":    sink_kind,
        "paths_found":  paths_found,
        "raw_output":   output,
    }
    return json.dumps(result, ensure_ascii=False, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# Tool 4: find_sanitizer_or_guard
# ──────────────────────────────────────────────────────────────────────────────
@mcp.tool()
def find_sanitizer_or_guard(
    file_path: str,
    function_name: str,
) -> str:
    """
    대상 함수 내에 sanitizer, validation, permission check, type check 등
    방어 코드(guard)가 존재하는지 Joern CPG 에서 확인한다.

    탐지 범주:
      - 입력 검증 함수: isset, empty, is_string, is_int, intval, filter_var, preg_match 등
      - 이스케이프/인코딩 함수: htmlspecialchars, htmlentities, addslashes, strip_tags 등
      - 권한/인증 체크: hash_equals, password_verify, check_admin, authorize 등
      - 예외/에러 처리: throw, trigger_error, die, exit

    Args:
        file_path:     CPG 에 로드된 파일 경로
        function_name: 분석할 함수 이름

    Returns:
        JSON 문자열 with keys:
          - has_sanitizer:   bool - sanitizer 계열 발견 여부
          - has_guard:       bool - guard/validation 계열 발견 여부
          - has_auth_check:  bool - 인증/권한 체크 발견 여부
          - has_error_exit:  bool - 예외/에러 처리 발견 여부
          - found_calls:     발견된 관련 함수 호출 목록 (함수명 + 줄 번호)
    """
    SANITIZER_FUNCS = [
        "htmlspecialchars", "htmlentities", "strip_tags", "addslashes",
        "mysql_real_escape_string", "mysqli_real_escape_string",
        "filter_var", "filter_input", "intval", "floatval", "boolval",
        "preg_match", "preg_replace", "trim", "urlencode", "base64_encode",
    ]
    GUARD_FUNCS = [
        "isset", "empty", "is_string", "is_int", "is_array", "is_null",
        "is_numeric", "ctype_alpha", "ctype_digit", "array_key_exists",
        "in_array", "validate", "sanitize", "check", "verify",
    ]
    AUTH_FUNCS = [
        "hash_equals", "password_verify", "check_admin", "is_admin",
        "authorize", "authenticate", "hasPermission", "checkToken",
        "hash_hmac",
    ]
    ERROR_FUNCS = [
        "throw", "trigger_error", "die", "exit", "abort",
    ]

    def _build_query(funcs: list[str]) -> str:
        pattern = "|".join(funcs)
        return (
            f'cpg.method.filename("{file_path}").name("{function_name}")'
            f'.call.name("({pattern})").map(c => s"${{c.name}} @ line ${{c.lineNumber}}").l'
        )

    san_raw   = _joern_query(_build_query(SANITIZER_FUNCS))
    guard_raw = _joern_query(_build_query(GUARD_FUNCS))
    auth_raw  = _joern_query(_build_query(AUTH_FUNCS))
    err_raw   = _joern_query(_build_query(ERROR_FUNCS))

    def _parse(raw: dict) -> list[str]:
        out = _fmt_joern(raw)
        if out.startswith("[Joern ERROR]") or out == "(no results)":
            return []
        return [l.strip() for l in out.splitlines() if l.strip()]

    san_calls   = _parse(san_raw)
    guard_calls = _parse(guard_raw)
    auth_calls  = _parse(auth_raw)
    err_calls   = _parse(err_raw)

    result = {
        "file_path":      file_path,
        "function":       function_name,
        "has_sanitizer":  len(san_calls) > 0,
        "has_guard":      len(guard_calls) > 0,
        "has_auth_check": len(auth_calls) > 0,
        "has_error_exit": len(err_calls) > 0,
        "found_calls": {
            "sanitizers":   san_calls,
            "guards":       guard_calls,
            "auth_checks":  auth_calls,
            "error_exits":  err_calls,
        },
    }
    return json.dumps(result, ensure_ascii=False, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# 엔트리포인트
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    _load_retriever_cache()
    # stdio transport: Codex CLI 가 subprocess 로 이 서버를 띄우고 stdin/stdout 으로 통신
    mcp.run(transport="stdio")
