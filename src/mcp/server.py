"""
NLD MCP Server
==============
Codex CLI 가 취약점 판단 시 호출하는 MCP tool server.

실행 방법:
    python3 -m src.mcp.server          # stdio transport (Codex CLI 연결용)
    python3 src/mcp/server.py          # 직접 실행 (동일)

Tools:
  0. check_cpg_status        - Joern workspace 상태 진단
  1. get_retrieved_knowledge - 사전 계산된 retriever 결과 조회
  2. get_cpg_summary         - Joern CPG 전체 요약 (call chain, params, reachable sinks)
  3. find_dataflow           - source → sink 데이터흐름 경로 추적
  4. find_sanitizer_or_guard - sanitizer / guard / validation 코드 존재 여부 확인
  5. read_source_context     - 특정 함수/라인 주변 source snippet 조회
  6. read_definition         - 심볼의 정의(함수/타입/필드 선언)를 ctags로 찾고, 필요 시 본문깉 추출한다.
  7. find_references         - 심볼/패턴의 사용처(호출부, 대입부, 전파 지점)를 ripgrep으로 빠르게 찾는다.
  8. map_vuln_context        - 함수 내부 취약 슬라이스(heuristic) 수집용.
  9. check_cpg_status        - Joern workspace 상태 진단

환경변수:
    RETRIEVER_OUTPUT_PATH   retriever 결과 JSON 경로
    JOERN_HOST              Joern REST server host (기본: localhost)
    JOERN_PORT              Joern REST server port (기본: 9000)
    JOERN_CONFIG            runner config 파일 이름 또는 절대경로
    REDIS_ENABLED           Redis 캐시 활성화 여부 (기본: false)
"""

from __future__ import annotations

# config 를 가장 먼저 import → .env 로드 + sys.path 설정이 선행됨
import src.mcp.config  # noqa: F401

from mcp.server.fastmcp import FastMCP

from src.mcp.tools import config_tools, cpg_tools, retriever_tools, source_tools
from src.mcp.tools.retriever_tools import load_retriever_cache

# ──────────────────────────────────────────────────────────────────────────────
# FastMCP 인스턴스
# ──────────────────────────────────────────────────────────────────────────────

mcp = FastMCP(
    name="nld-vulnerability-analysis",
    instructions=(
        "NLD memory-corruption 취약점 분석용 MCP server입니다.\n"
        "목표: 실제 trigger 가능한 메모리 손상 취약점만 식별하고, 추측을 배제한다.\n\n"
        "=== Tool 역할(전역 지침) ===\n"
        "- check_cpg_status: CPG/overlay 상태 진단. 분석 시작 전에 1회 확인.\n"
        "- get_retrieved_knowledge: 유사 CVE/패턴 힌트. 참고용이며 단독 근거로 판정 금지.\n"
        "- get_cpg_summary: 함수 식별, caller/callee, callsite, 구조 파악.\n"
        "- find_dataflow: source->sink 경로 증거 확보(가장 강한 CPG 근거).\n"
        "- find_sanitizer_or_guard: validation/sanitizer/guard 존재 및 지배 여부 확인.\n"
        "- map_vuln_context: 함수 내부 취약 슬라이스(heuristic) 수집용.\n"
        "- read_source_context/read_definition/find_references: 최종 코드 사실 검증용.\n\n"
        "=== 권장 판단 순서 ===\n"
        "1) check_cpg_status로 CPG 건강 상태를 확인한다.\n"
        "2) get_retrieved_knowledge로 잠재 유형을 좁히되, 가설로만 사용한다.\n"
        "3) get_cpg_summary로 타겟 함수 매칭/호출 경계를 확정한다.\n"
        "4) find_dataflow로 source->sink 경로를 확인한다.\n"
        "5) find_sanitizer_or_guard로 guard/sanitizer가 sink를 지배하는지 확인한다.\n"
        "6) map_vuln_context로 로컬 위험 연산(크기/인덱스/alloc-free-use)을 수집한다.\n"
        "7) read_source_context/read_definition으로 최종 사실관계를 검증한다.\n\n"
        "=== 증거 기준 ===\n"
        "- High confidence: attacker-controlled source -> memory sink 경로 + guard 부재/불충분.\n"
        "- Medium: 경로 일부만 확인되었으나 코드상 위험 연산이 명확.\n"
        "- Low/Reject: source 불명확, 경로 불명확, 방어코드가 지배함.\n"
        "- flow_count=0은 '안전'의 증거가 아니다. source code 직접 검증을 계속한다.\n\n"
        "=== 불일치 처리 규칙 ===\n"
        "- CPG 결과와 host source/diff 코드가 다르면 source code를 우선한다.\n"
        "- function not found/candidate_count=0이면 경로/함수명/버전 불일치를 명시한다.\n"
        "- CPG는 후보 압축 및 보강 근거, 최종 판정은 코드 사실 기반으로 수행한다."
    ),
)

# ──────────────────────────────────────────────────────────────────────────────
# Tool 등록
# ──────────────────────────────────────────────────────────────────────────────

config_tools.register(mcp)
retriever_tools.register(mcp)
cpg_tools.register(mcp)
source_tools.register(mcp)

# ──────────────────────────────────────────────────────────────────────────────
# 엔트리포인트
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    load_retriever_cache()
    # stdio transport: Codex CLI 가 subprocess 로 이 서버를 띄우고 stdin/stdout 으로 통신
    mcp.run(transport="stdio")
