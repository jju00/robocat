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
        "NLD 취약점 탐지 파이프라인의 MCP server입니다.\n"
        "사용 가능한 tool:\n"
        "  0. check_cpg_status          - Joern workspace 상태 진단\n"
        "  1. get_retrieved_knowledge   - 사전 계산된 CVE 지식 조회\n"
        "  2. get_cpg_summary           - Joern CPG 요약 (call chain, params, sinks)\n"
        "  3. find_dataflow             - source → sink 데이터흐름 경로\n"
        "  4. find_sanitizer_or_guard   - sanitizer / validation / guard 존재 여부\n"
        "  5. read_source_context       - 특정 함수/라인 주변 source snippet 조회\n\n"
        "취약점 판단 순서 권장:\n"
        "  1. get_retrieved_knowledge 로 관련 CVE 지식 확인\n"
        "  2. get_cpg_summary 로 함수 구조/호출 흐름 파악\n"
        "  3. find_dataflow 로 user input → sink 경로 존재 여부 확인\n"
        "  4. find_sanitizer_or_guard 로 방어 코드 존재 여부 확인\n"
        "  5. 1~4 결과를 종합하여 취약(YES) / 안전(NO) / 불확실(-1) 판정"
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
