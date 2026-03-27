"""
NLD MCP Server
==============
Codex CLI 가 취약점 판단 시 호출하는 MCP tool server.

실행 방법:
    python3 -m src.mcp.server          # stdio transport (Codex CLI 연결용)
    python3 src/mcp/server.py          # 직접 실행 (동일)

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

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

# ── 경로 설정은 상수 정의 전에 먼저 수행 ──────────────────────────────────────
_ROOT = Path(__file__).resolve().parents[2]   # src/mcp/server.py → NLD/
load_dotenv(_ROOT / ".env")
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "scripts" / "joern"))

from src.utils.joern_server import JoernClient           # noqa: E402
from src.utils.joern_executor import JoernExecutor       # noqa: E402
from query_builders.call_context import CallContextQueryBuilder  # noqa: E402  # type: ignore[import]

# ──────────────────────────────────────────────────────────────────────────────
# 경로 / 환경변수 설정
# ──────────────────────────────────────────────────────────────────────────────
RETRIEVER_OUTPUT_PATH = Path(
    os.getenv("RETRIEVER_OUTPUT_PATH", str(_ROOT / "data" / "retriever" / "retriever_output.json"))
)
DIFF_RETRIEVER_PATH = Path(
    os.getenv("DIFF_RETRIEVER_PATH", str(_ROOT / "data" / "diff" / "diff_retriever.json"))
)

# 기본값 fallback (env에서 동적으로 나중에 읽어서 overwrite)
JOERN_HOST = os.getenv("JOERN_HOST", "localhost")
JOERN_PORT = int(os.getenv("JOERN_PORT", "9000"))

# ── 타겟별 Joern 설정: JOERN_CONFIG 로 runner config 파일을 선택 ───────────────
_CONFIGS_DIR = _ROOT / "scripts" / "joern" / "runners" / "configs"


def _load_runner_config() -> dict[str, Any]:
    """
    JOERN_CONFIG 환경변수로 지정한 runner config JSON을 로드하고 반환.

    지정 방법:
        JOERN_CONFIG=lighttpd           # configs/ 디렉토리 기준 이름 (확장자 생략 가능)
        JOERN_CONFIG=lighttpd.json      # 동일
        JOERN_CONFIG=/abs/path/foo.json # 절대경로

    값이 없거나 파일이 없으면 빈 dict 반환.
    """
    name = os.getenv("JOERN_CONFIG", "")
    if not name:
        return {}

    path = Path(name)
    if not path.is_absolute():
        # configs 디렉토리 기준 탐색, 확장자 없으면 .json 추가
        path = _CONFIGS_DIR / (name if "." in name else f"{name}.json")

    if not path.exists():
        print(f"[NLD-MCP] WARNING: JOERN_CONFIG not found: {path}", file=sys.stderr)
        return {}

    raw = path.read_text(encoding="utf-8")
    return json.loads(os.path.expandvars(raw))


_runner_cfg = _load_runner_config()

JOERN_PROJECT_NAME = _runner_cfg.get("joern",  {}).get("workspace_project",    "")
JOERN_LANGUAGE     = _runner_cfg.get("project", {}).get("language",            "php")
JOERN_TARGET_PATH  = _runner_cfg.get("paths",   {}).get("container_source_root", "/app/source")

# ── Joern executor / builder (lazy singleton) ─────────────────────────────────
_executor: JoernExecutor | None = None
_call_context_builder: CallContextQueryBuilder | None = None

# CPG 로드 / ossdataflow 실행 여부 (프로세스 수명 동안 1회만 실행)
_cpg_ready: bool = False
_dataflow_ready: bool = False
# import_cpg.scala 가 반환한 실제 workspace 프로젝트 이름 (설정값과 다를 수 있음)
_actual_project_name: str = ""


def _get_executor() -> JoernExecutor:
    global _executor
    if _executor is None:
        _executor = JoernExecutor(JoernClient(url=f"{JOERN_HOST}:{JOERN_PORT}"))
    return _executor


def _get_call_context_builder() -> CallContextQueryBuilder:
    global _call_context_builder
    # _actual_project_name 이 세팅된 뒤에 호출되므로 실제 workspace 이름을 사용
    project_name = _actual_project_name or JOERN_PROJECT_NAME
    if _call_context_builder is None or _call_context_builder.project_name != project_name:
        _call_context_builder = CallContextQueryBuilder(
            project_name=project_name,
            language=JOERN_LANGUAGE,
            target_path=JOERN_TARGET_PATH,
        )
    return _call_context_builder


def _import_cpg_kwargs(run_dataflow: bool = False) -> dict[str, str]:
    """import_cpg.scala 에 전달할 템플릿 변수 dict."""
    return {
        "JOERN_IMPORT":  JOERN_LANGUAGE,
        "TARGET_PATH":   JOERN_TARGET_PATH,
        "PROJECT_NAME":  JOERN_PROJECT_NAME,
        "LANGUAGE":      JOERN_LANGUAGE,
        "RUN_DATAFLOW":  "true" if run_dataflow else "false",
    }


def _build_cpg_header(run_dataflow: bool = False) -> str:
    """
    import_cpg.scala 를 로드·치환하여 CPG setup 헤더 문자열을 반환.

    Joern /query-sync 는 요청 간 state를 유지하지 않으므로,
    모든 CPG 쿼리는 이 헤더를 앞에 붙여 단일 요청으로 전송한다.
    """
    executor = _get_executor()
    template = executor.load_scala_template("import_cpg.scala")
    return executor.fill_template(template, **_import_cpg_kwargs(run_dataflow=run_dataflow))


async def _run_cpg_query(query: str, run_dataflow: bool = False) -> dict[str, Any]:
    """
    CPG 헤더(import + open) + 실제 쿼리를 단일 Joern 요청으로 실행.

    Joern REST 서버가 요청 간 REPL state를 유지하지 않는 환경에서도
    매 요청마다 CPG가 열려 있음을 보장한다.
    """
    header = _build_cpg_header(run_dataflow=run_dataflow)
    combined = header + "\n\n" + query
    return await _get_executor().run_query(combined)

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
# Joern 결과 포맷 헬퍼
# ──────────────────────────────────────────────────────────────────────────────
def _fmt_executor(result: dict[str, Any]) -> str:
    """
    executor.run_query() 결과를 Codex 가 읽기 좋은 문자열로 정규화.

    JSON 파싱에 실패한 인라인 DSL 쿼리(Tool 3/4)는 stdout 원문을 그대로 반환.
    """
    if not result.get("success"):
        err = result.get("stderr") or "Unknown Joern error"
        return f"[Joern ERROR] {err}"
    out = result.get("stdout", "").strip()
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
# Tool 0: check_cpg_status  (진단용)
# ──────────────────────────────────────────────────────────────────────────────
@mcp.tool()
async def check_cpg_status() -> str:
    """
    Joern workspace 의 현재 상태를 반환한다 (진단용).

    CPG 쿼리 전에 호출하면 프로젝트가 로드됐는지, 어떤 이름으로 저장됐는지 확인할 수 있다.
    CPG import 헤더 없이 순수 Joern 상태를 조회한다.

    Returns:
        JSON 문자열 with keys:
          - workspace_projects: workspace 에 저장된 프로젝트 이름 목록
          - active_cpg_root:    현재 활성 CPG 의 root 경로 (없으면 "none")
          - joern_version:      Joern 버전 문자열
    """
    q = """
import ujson._

val projects = workspace.projects.map(_.name).l
val activeRoot = try {
  cpg.metaData.l.headOption.map(_.root).getOrElse("(empty cpg)")
} catch {
  case _: Throwable => "none"
}

val out = Map(
  "workspace_projects" -> projects,
  "active_cpg_root"    -> activeRoot
)

println("OUTPUT: " + ujson.write(ujson.read(out.toJson)))
"""
    result = await _get_executor().run_query(q)
    return _fmt_executor(result)


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
async def get_cpg_summary(
    file_path: str,
    function_name: str,
) -> str:
    """
    Joern CPG(Code Property Graph) 에서 대상 함수의 구조/호출 흐름 요약을 반환한다.

    method_call_context.scala 쿼리를 사용하여 단일 요청으로 callee/caller 전체를 조회한다.

    포함 정보:
      - 함수 시그니처 (full name, 파일, 라인)
      - 직접 호출하는 함수 목록 (callees): call_name, callee_full_name, call_code, line
      - 이 함수를 호출하는 함수 목록 (callers): caller_method_name, call_code, line

    Args:
        file_path:     CPG 에 로드된 프로젝트 내 파일 경로
                       (예: "libraries/classes/Advisor.php")
        function_name: 분석할 함수 이름.
                       "ClassName::method" 형식이면 메서드명만 자동 파싱.
                       (예: "Advisor::evaluateRuleExpression" 또는 "evaluateRuleExpression")

    Returns:
        JSON 문자열 with keys: result_count, results (method_name, signature,
        callee_count, caller_count, callees, callers)
    """
    query = _get_call_context_builder().build_call_context_query(file_path, function_name)
    result = await _run_cpg_query(query)

    parsed = result.get("parsed", {})

    if not result.get("success"):
        return json.dumps(
            {"error": _fmt_executor(result), "file_path": file_path, "function": function_name},
            ensure_ascii=False, indent=2,
        )

    if "raw_stdout" in parsed:
        return json.dumps(
            {"error": "CPG 쿼리 파싱 실패", "raw_stdout": parsed["raw_stdout"],
             "file_path": file_path, "function": function_name},
            ensure_ascii=False, indent=2,
        )

    return json.dumps(parsed, ensure_ascii=False, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# Tool 3: find_dataflow
# ──────────────────────────────────────────────────────────────────────────────
@mcp.tool()
async def find_dataflow(
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
          - raw_output: Joern 원본 출력
    """
    q_dataflow = (
        f'val src = cpg.method.filename("{file_path}").name("{function_name}")'
        f'.parameter.l\n'
        f'val sink = cpg.call.name("{sink_kind}").l\n'
        f'sink.reachableByFlows(src).p'
    )

    raw = await _run_cpg_query(q_dataflow, run_dataflow=True)
    output = _fmt_executor(raw)

    lines = [ln for ln in output.splitlines() if ln.strip()]
    paths_found = sum(1 for ln in lines if "→" in ln or "Flow" in ln or "Parameter" in ln)

    result = {
        "file_path":   file_path,
        "function":    function_name,
        "sink_kind":   sink_kind,
        "paths_found": paths_found,
        "raw_output":  output,
    }
    return json.dumps(result, ensure_ascii=False, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# Tool 4: find_sanitizer_or_guard
# ──────────────────────────────────────────────────────────────────────────────
@mcp.tool()
async def find_sanitizer_or_guard(
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

    san_raw   = await _run_cpg_query(_build_query(SANITIZER_FUNCS))
    guard_raw = await _run_cpg_query(_build_query(GUARD_FUNCS))
    auth_raw  = await _run_cpg_query(_build_query(AUTH_FUNCS))
    err_raw   = await _run_cpg_query(_build_query(ERROR_FUNCS))

    def _parse(raw: dict) -> list[str]:
        out = _fmt_executor(raw)
        if out.startswith("[Joern ERROR]") or out == "(no results)":
            return []
        return [ln.strip() for ln in out.splitlines() if ln.strip()]

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
