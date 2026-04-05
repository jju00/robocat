"""Tools 2-4: CPG analysis
=========================
• get_cpg_summary       — 함수 구조/호출 흐름 요약
• find_dataflow         — source → sink 데이터흐름 경로
• find_sanitizer_or_guard — sanitizer / guard 존재 여부

+ 내부 헬퍼
  - Joern executor / builder 싱글턴
  - CPG 쿼리 실행 (_run_cpg_query)
  - Redis revision 관리 (_compute_cpg_revision, _ensure_cpg_revision)
  - Joern 결과 포맷 (_fmt_executor)
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

from src.mcp.config import (
    CONFIGS_DIR,
    JOERN_HOST,
    JOERN_IMPORT,
    JOERN_LANGUAGE,
    JOERN_PORT,
    JOERN_PROJECT_NAME,
    JOERN_SANITIZERS,
    JOERN_SINKS,
    JOERN_SOURCES,
    JOERN_TARGET_PATH,
)
from src.utils.joern_executor import JoernExecutor       # noqa: E402
from src.utils.joern_server import JoernClient           # noqa: E402
from src.utils.redis_cache import RedisCache             # noqa: E402
from query_builders.call_context import CallContextQueryBuilder  # noqa: E402  # type: ignore[import]
from query_builders.taint import TaintQueryBuilder       # noqa: E402  # type: ignore[import]

# ──────────────────────────────────────────────────────────────────────────────
# Singleton 상태
# ──────────────────────────────────────────────────────────────────────────────

_executor:             JoernExecutor | None            = None
_call_context_builder: CallContextQueryBuilder | None  = None
_taint_builder:        TaintQueryBuilder | None        = None

# import_cpg.scala 가 반환한 실제 workspace 프로젝트 이름 (설정값과 다를 수 있음)
_actual_project_name: str = ""

# Redis 캐시
_cache = RedisCache()
_CPG_SUMMARY_CACHE_VER = "v5"
_DATAFLOW_CACHE_VER = "v5"
_GUARD_CACHE_VER = "v4"

# ──────────────────────────────────────────────────────────────────────────────
# Joern 싱글턴 헬퍼
# ──────────────────────────────────────────────────────────────────────────────


def _get_executor() -> JoernExecutor:
    global _executor
    if _executor is None:
        _executor = JoernExecutor(JoernClient(url=f"{JOERN_HOST}:{JOERN_PORT}"))
    return _executor


def _get_call_context_builder() -> CallContextQueryBuilder:
    global _call_context_builder
    project_name = _actual_project_name or JOERN_PROJECT_NAME
    if _call_context_builder is None or _call_context_builder.project_name != project_name:
        _call_context_builder = CallContextQueryBuilder(
            project_name=project_name,
            language=JOERN_LANGUAGE,
            target_path=JOERN_TARGET_PATH,
        )
    return _call_context_builder


def _get_taint_builder() -> TaintQueryBuilder:
    global _taint_builder
    project_name = _actual_project_name or JOERN_PROJECT_NAME
    if _taint_builder is None or _taint_builder.project_name != project_name:
        _taint_builder = TaintQueryBuilder(
            project_name=project_name,
            target_path=JOERN_TARGET_PATH,
            language=JOERN_LANGUAGE,
            joern_import=JOERN_IMPORT,
            source_rules=JOERN_SOURCES,
        )
    return _taint_builder

# ──────────────────────────────────────────────────────────────────────────────
# CPG 쿼리 실행
# ──────────────────────────────────────────────────────────────────────────────


def _import_cpg_kwargs(ensure_overlays: bool = False) -> dict[str, str]:
    """import_cpg.scala 에 전달할 템플릿 변수 dict."""
    return {
        "JOERN_IMPORT":    JOERN_LANGUAGE,
        "TARGET_PATH":     JOERN_TARGET_PATH,
        "PROJECT_NAME":    JOERN_PROJECT_NAME,
        "LANGUAGE":        JOERN_LANGUAGE,
        "ENSURE_OVERLAYS": "true" if ensure_overlays else "false",
    }


def _build_cpg_header(ensure_overlays: bool = False) -> str:
    """
    import_cpg.scala 를 로드·치환하여 CPG setup 헤더 문자열을 반환.

    Joern /query-sync 는 요청 간 state를 유지하지 않으므로,
    모든 CPG 쿼리는 이 헤더를 앞에 붙여 단일 요청으로 전송한다.

    ensure_overlays=True 이면 callgraph + ossdataflow 오버레이까지 적용한다.
    m.callee / m.caller 등 callgraph 기반 쿼리나 reachableByFlows 를 사용하는
    쿼리는 반드시 이 플래그를 True 로 설정해야 한다.
    """
    executor = _get_executor()
    template = executor.load_scala_template("import_cpg.scala")
    return executor.fill_template(template, **_import_cpg_kwargs(ensure_overlays=ensure_overlays))


async def _run_cpg_query(query: str, ensure_overlays: bool = False) -> dict[str, Any]:
    """
    CPG 헤더(import + open) + 실제 쿼리를 단일 Joern 요청으로 실행.

    Joern REST 서버가 요청 간 REPL state를 유지하지 않는 환경에서도
    매 요청마다 CPG가 열려 있음을 보장한다.

    ensure_overlays=True 이면 헤더에서 callgraph + ossdataflow 오버레이를 적용한다.
    """
    header = _build_cpg_header(ensure_overlays=ensure_overlays)
    combined = header + "\n\n" + query
    return await _get_executor().run_query(combined)


def _fmt_executor(result: dict[str, Any]) -> str:
    """
    executor.run_query() 결과를 Codex 가 읽기 좋은 문자열로 정규화.

    JSON 파싱에 실패한 인라인 DSL 쿼리는 stdout 원문을 그대로 반환.
    """
    if not result.get("success"):
        err = result.get("stderr") or "Unknown Joern error"
        return f"[Joern ERROR] {err}"
    out = result.get("stdout", "").strip()
    return out if out else "(no results)"

# ──────────────────────────────────────────────────────────────────────────────
# CPG Revision 관리
# ──────────────────────────────────────────────────────────────────────────────


def _compute_cpg_revision() -> str:
    """
    현재 CPG 대상 소스의 revision 식별자를 계산한다.

    우선순위:
      1. JOERN_TARGET_PATH 의 git HEAD short hash (host에서 접근 가능한 경우)
      2. JOERN_CONFIG 파일 내용의 SHA-1 hash (앞 10자리)
      3. fallback: JOERN_PROJECT_NAME + JOERN_TARGET_PATH 조합 hash
    """
    # 1) git hash
    try:
        r = subprocess.run(
            ["git", "-C", JOERN_TARGET_PATH, "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            rev = r.stdout.strip()
            if rev:
                return rev
    except Exception:
        pass

    # 2) runner config 파일 내용 hash
    cfg_name = os.getenv("JOERN_CONFIG", "")
    if cfg_name:
        _p = Path(cfg_name)
        cfg_path = _p if _p.is_absolute() else (
            CONFIGS_DIR / (cfg_name if "." in cfg_name else f"{cfg_name}.json")
        )
        if cfg_path.exists():
            return hashlib.sha1(cfg_path.read_bytes()).hexdigest()[:10]

    # 3) fallback
    raw = f"{JOERN_PROJECT_NAME}:{JOERN_TARGET_PATH}"
    return hashlib.sha1(raw.encode()).hexdigest()[:10]


async def _ensure_cpg_revision() -> str:
    """
    현재 CPG revision을 확인하고 Redis의 active revision과 비교한다.

    revision이 변경된 경우:
      - old revision에 속한 캐시 키를 모두 삭제
      - active revision을 new revision으로 갱신

    Returns:
        현재 유효한 revision 문자열
    """
    project = _actual_project_name or JOERN_PROJECT_NAME
    new_rev = _compute_cpg_revision()

    if not project or not _cache.enabled:
        return new_rev

    old_rev = await _cache.get_active_revision(project)
    if old_rev != new_rev:
        if old_rev:
            await _cache.clear_revision_cache(project, old_rev)
            print(
                f"[NLD-MCP] CPG revision changed: {old_rev} → {new_rev}, "
                "old cache cleared.",
                file=sys.stderr,
            )
        await _cache.set_active_revision(project, new_rev)

    return new_rev

# ──────────────────────────────────────────────────────────────────────────────
# Tool 2: get_cpg_summary
# ──────────────────────────────────────────────────────────────────────────────


async def get_cpg_summary(
    file_path: str,
    function_name: str,
    depth: int = 1,
    duplicate_mode: str = "auto",
    target_line: int = -1,
) -> str:
    """
    Joern CPG(Code Property Graph) 에서 대상 함수의 구조/호출 흐름 요약을 반환한다.

    method_call_context.scala 쿼리를 사용하여 단일 요청으로 callee/caller 전체를 조회한다.
    파일 경로 매칭 실패 시 3단계 폴백(exact → non-external → endsWith)을 적용하고,
    non-external + 큰 AST 순으로 정렬하여 definition 을 우선 반환한다.

    포함 정보:
      - 함수 시그니처 (method_name, method_full_name, signature, file, line, ast_size)
      - 직접 호출하는 함수 목록 (callees): method_name, method_full_name, signature, file, line,
        callsite_file, callsite_line, callsite_lines[]
      - 이 함수를 호출하는 함수 목록 (callers): method_name, method_full_name, signature, file, line,
        callsite_file, callsite_line, callsite_lines[]
      - duplicate 해소 모드:
        auto(기본) | exact_file | exact_file_line(target_line 필요)
      - depth: call graph 확장 깊이 (기본 1)

    Args:
        file_path:     CPG 에 로드된 프로젝트 내 파일 경로
                       (예: "libraries/classes/Advisor.php")
        function_name: 분석할 함수 이름.
                       "ClassName::method" 형식이면 메서드명만 자동 파싱.
                       (예: "Advisor::evaluateRuleExpression" 또는 "evaluateRuleExpression")
        depth:         call graph 확장 깊이 (1 이상, 기본 1)
        duplicate_mode: duplicate 함수 선택 모드
                        auto | exact_file | exact_file_line
        target_line:   exact_file_line 모드에서 강제 매칭할 함수 정의 line

    Returns:
        JSON 문자열 with keys:
          - project_name:        임포트된 프로젝트 이름
          - query_file_path:     요청한 파일 경로
          - query_function_name: 요청한 함수 이름
          - matched_file:        실제 매칭된 파일 경로 (디버깅용)
          - matched_full_name:   실제 매칭된 메서드 full name (디버깅용)
          - candidate_count:     폴백 후 후보 메서드 수
          - result_count:        정렬 후 반환된 결과 수
          - results:             메서드별 상세 정보 목록
              (method_name, method_full_name, signature, file, line, ast_size,
               callee_count, caller_count, callees, callers)
              where callees/callers entries include:
              callsite_file, callsite_line, callsite_lines
    """
    project = _actual_project_name or JOERN_PROJECT_NAME
    revision = await _ensure_cpg_revision()
    cache_key = _cache.make_cpg_summary_key(
        project,
        revision,
        file_path,
        (
            f"{function_name}:{_CPG_SUMMARY_CACHE_VER}"
            f":d{max(1, int(depth))}"
            f":m{(duplicate_mode or 'auto').strip().lower()}"
            f":l{int(target_line)}"
        ),
    )

    cached = await _cache.get_json(cache_key)
    if cached is not None:
        return json.dumps(cached, ensure_ascii=False, indent=2)

    mode = (duplicate_mode or "auto").strip().lower()
    line = int(target_line)

    # exact_file_line 실패 시 line window + mode fallback:
    # exact_file_line(start) -> ±1, ±2 -> exact_file -> auto
    attempts: list[tuple[str, int]] = []
    if mode == "exact_file_line":
        attempts.append(("exact_file_line", line))
        if line > 0:
            for delta in (1, 2):
                if line - delta > 0:
                    attempts.append(("exact_file_line", line - delta))
                attempts.append(("exact_file_line", line + delta))
        attempts.append(("exact_file", -1))
        attempts.append(("auto", -1))
    elif mode == "exact_file":
        attempts = [("exact_file", -1), ("auto", -1)]
    else:
        attempts = [(mode if mode in {"auto", "exact_file", "exact_file_line"} else "auto", line)]

    # 중복 시도 제거(순서 유지)
    dedup_attempts: list[tuple[str, int]] = []
    seen_attempts: set[tuple[str, int]] = set()
    for item in attempts:
        if item in seen_attempts:
            continue
        seen_attempts.add(item)
        dedup_attempts.append(item)

    parsed: dict[str, Any] = {}
    last_error: Optional[dict[str, Any]] = None

    for attempt_mode, attempt_line in dedup_attempts:
        query = _get_call_context_builder().build_call_context_query(
            file_path=file_path,
            function_name=function_name,
            depth=depth,
            duplicate_mode=attempt_mode,
            target_line=attempt_line,
        )
        # callgraph 오버레이가 필요해야 m.callee / m.caller 가 올바르게 동작한다.
        result = await _run_cpg_query(query, ensure_overlays=True)
        parsed = result.get("parsed", {})

        if not result.get("success"):
            last_error = {
                "error": _fmt_executor(result),
                "file_path": file_path,
                "function": function_name,
            }
            continue

        if "raw_stdout" in parsed:
            last_error = {
                "error": "CPG 쿼리 파싱 실패",
                "raw_stdout": parsed["raw_stdout"],
                "file_path": file_path,
                "function": function_name,
            }
            continue

        result_count = 0
        raw_count = parsed.get("result_count", 0)
        try:
            result_count = int(raw_count)
        except Exception:
            result_count = len(parsed.get("results", []) or [])

        if result_count > 0:
            break
    else:
        if last_error is not None:
            return json.dumps(last_error, ensure_ascii=False, indent=2)

    await _cache.set_json(cache_key, parsed, project=project, revision=revision)
    return json.dumps(parsed, ensure_ascii=False, indent=2)

# ──────────────────────────────────────────────────────────────────────────────
# Tool 3: find_dataflow
# ──────────────────────────────────────────────────────────────────────────────


async def find_dataflow(
    file_path: str,
    function_name: str,
    sink_kind: str = "memory",
) -> str:
    """
    TaintQueryBuilder + taint_flow.scala 를 사용하여
    source → sink 데이터흐름 경로를 반환한다.

    - 기본 케이스: 전역 source → 타겟 함수 내부 sink
    - 추가 케이스 1: 타겟 함수 내부 source(파라미터/field access) → 타겟 함수 내부 sink
    - 추가 케이스 2: 타겟 함수 내부 source(파라미터/field access) → 전역 sink
    - 각 flow 노드는 role(source/sink/intermediate)로 태깅된 최소 증거 라인.
    - 파일 경로는 TARGET_PATH 기준 상대 경로로 출력.
    - uaf_meta(alloc_sites, free_sites, post_free_use)를 함께 반환.

    Args:
        file_path:     분석 대상 파일 경로 (CPG 내 경로 suffix)
        function_name: 분석 대상 함수 이름
        sink_kind:     추적할 sink 카테고리 (기본: "memory").
                       JOERN_SINKS 에 정의된 키(예: "memory_expr") 또는 임의 함수명 regex.

    Returns:
        JSON 문자열.
        keys: project_name, language, target_file, target_function,
              sink_name, source_count, internal_source_count,
              effective_source_count, sink_count, global_sink_count, flow_count,
              flows[].{case_kind, post_free_use, nodes[].{role, line, code, type, file}},
              uaf_meta.{alloc_sites, free_sites}
    """
    project = _actual_project_name or JOERN_PROJECT_NAME
    revision = await _ensure_cpg_revision()
    cache_key = (
        f"nld:dataflow:{project}:rev{revision}:{_DATAFLOW_CACHE_VER}"
        f":{file_path}:{function_name}:{sink_kind}"
    )

    cached = await _cache.get_json(cache_key)
    if cached is not None:
        return json.dumps(cached, ensure_ascii=False, indent=2)

    sink_regex = JOERN_SINKS.get(sink_kind, {}).get("regex", sink_kind)

    try:
        query = _get_taint_builder().build_taint_query(
            sink_kind,
            sink_regex,
            file_path=file_path,
            function_name=function_name,
        )
    except ValueError as exc:
        return json.dumps(
            {"error": str(exc), "sink_kind": sink_kind},
            ensure_ascii=False, indent=2,
        )

    raw = await _run_cpg_query(query, ensure_overlays=True)

    if not raw.get("success"):
        return json.dumps(
            {"error": _fmt_executor(raw), "sink_kind": sink_kind},
            ensure_ascii=False, indent=2,
        )

    parsed = raw.get("parsed", {})

    # 기본 memory 분석 결과가 약한 경우, memory_expr를 조건부로 추가 실행해
    # 연산자 기반 위험(인덱싱/산술) 후보를 보강한다.
    if sink_kind == "memory" and "memory_expr" in JOERN_SINKS:
        def _to_int(v: Any, default: int = 0) -> int:
            try:
                return int(v)
            except Exception:
                return default

        flow_count = _to_int(parsed.get("flow_count"))
        sink_count = _to_int(parsed.get("sink_count"))
        uaf_meta = parsed.get("uaf_meta") if isinstance(parsed.get("uaf_meta"), dict) else {}
        has_alloc_free = bool(uaf_meta.get("alloc_sites")) or bool(uaf_meta.get("free_sites"))

        # 위험 신호 추출: 큰 callee 수 + 연산자 사용 빈도
        callee_count = 0
        risky_expr_op_count = 0
        try:
            summary_raw = await get_cpg_summary(
                file_path=file_path,
                function_name=function_name,
                depth=1,
            )
            summary = json.loads(summary_raw)
            if isinstance(summary, dict):
                results = summary.get("results") or []
                if isinstance(results, list) and results:
                    first = results[0] if isinstance(results[0], dict) else {}
                    callee_count = _to_int(first.get("callee_count"))
        except Exception:
            callee_count = 0

        try:
            expr_probe = (
                'import ujson._\n'
                f'val target = cpg.method.nameExact("{TaintQueryBuilder.escape(function_name)}")'
                f'.filter(m => !m.isExternal && m.filename.endsWith("{TaintQueryBuilder.escape(file_path)}")).l\n'
                'val c = target.iterator.flatMap(_.ast.isCall.name("(<operator>\\\\.indirectIndexAccess|<operator>\\\\.addition|<operator>\\\\.subtraction|<operator>\\\\.multiplication)").l).size\n'
                'val __OUTPUT__ = ujson.write(ujson.Obj("count" -> c))\n'
            )
            expr_probe_raw = await _run_cpg_query(expr_probe, ensure_overlays=True)
            expr_probe_parsed = expr_probe_raw.get("parsed", {}) if isinstance(expr_probe_raw, dict) else {}
            if isinstance(expr_probe_parsed, dict):
                risky_expr_op_count = _to_int(expr_probe_parsed.get("count"))
        except Exception:
            risky_expr_op_count = 0

        reasons: list[str] = []
        if sink_count <= 1:
            reasons.append("low_sink_count")
        if flow_count == 0 and callee_count >= 80:
            reasons.append("high_callee_count")
        if flow_count == 0 and risky_expr_op_count >= 12:
            reasons.append("many_risky_expr_ops")
        if flow_count == 0 and has_alloc_free:
            reasons.append("alloc_or_free_present")

        should_expand = len(reasons) > 0
        if should_expand:
            expr_regex = JOERN_SINKS["memory_expr"].get("regex", "NEVER_MATCH_ANYTHING")
            expr_query = _get_taint_builder().build_taint_query(
                "memory_expr",
                expr_regex,
                file_path=file_path,
                function_name=function_name,
            )
            expr_raw = await _run_cpg_query(expr_query, ensure_overlays=True)
            expr_parsed = expr_raw.get("parsed", {}) if expr_raw.get("success") else {
                "error": _fmt_executor(expr_raw),
            }

            expr_sink_count = _to_int(expr_parsed.get("sink_count")) if isinstance(expr_parsed, dict) else 0
            expr_flow_count = _to_int(expr_parsed.get("flow_count")) if isinstance(expr_parsed, dict) else 0

            parsed["extended_analysis"] = {
                "triggered": True,
                "reasons": reasons,
                "signals": {
                    "callee_count": callee_count,
                    "risky_expr_op_count": risky_expr_op_count,
                    "has_alloc_or_free": has_alloc_free,
                    "memory_sink_count": sink_count,
                    "memory_flow_count": flow_count,
                },
                "memory_expr": expr_parsed,
            }
            parsed["effective_sink_count"] = sink_count + expr_sink_count
            parsed["effective_flow_count"] = flow_count + expr_flow_count
        else:
            parsed["extended_analysis"] = {
                "triggered": False,
                "reasons": [],
                "signals": {
                    "callee_count": callee_count,
                    "risky_expr_op_count": risky_expr_op_count,
                    "has_alloc_or_free": has_alloc_free,
                    "memory_sink_count": sink_count,
                    "memory_flow_count": flow_count,
                },
            }

    await _cache.set_json(cache_key, parsed, project=project, revision=revision)
    return json.dumps(parsed, ensure_ascii=False, indent=2)

# ──────────────────────────────────────────────────────────────────────────────
# Tool 4: find_sanitizer_or_guard
# ──────────────────────────────────────────────────────────────────────────────


async def find_sanitizer_or_guard(
    file_path: str,
    function_name: str,
    sink_kind: Optional[str] = None,
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
          - protection_analysis.guard_dominance:
              total_sinks, sinks_with_dominating_guard, sink_guard_mappings[]
              (sink_line, sink_expression, related_guards[{name,line,expression}],
               guard_dominates_sink)
    """
    project = _actual_project_name or JOERN_PROJECT_NAME
    revision = await _ensure_cpg_revision()
    sink_cache_key = sink_kind or "none"
    cache_key = _cache.make_guard_key(
        project, revision, file_path, f"{function_name}:{sink_cache_key}:{_GUARD_CACHE_VER}"
    )

    cached = await _cache.get_json(cache_key)
    if cached is not None:
        return json.dumps(cached, ensure_ascii=False, indent=2)

    SANITIZER_FUNCS = JOERN_SANITIZERS or [
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

    def _build_query(funcs: list[str]) -> str:  # noqa: ARG001  (funcs used in f-string below)
        return (
            'import ujson._\n'
            'val __OUTPUT__ = {\n'
            f'  val targetFile = "{file_path}"\n'
            f'  val targetFunction = "{function_name}"\n'
            '  val targetMethods = cpg.method\n'
            '    .nameExact(targetFunction)\n'
            '    .filter(m => !m.isExternal)\n'
            '    .filter(m => m.filename.endsWith(targetFile))\n'
            '    .l\n'
            '  val found = targetMethods.flatMap('
            '_.ast.isCall.map(c => ujson.Obj("name" -> c.name, "line" -> c.lineNumber.getOrElse(-1))).l)\n'
            '  ujson.write(found)\n'
            '}'
        )

    san_raw   = await _run_cpg_query(_build_query(SANITIZER_FUNCS))
    guard_raw = await _run_cpg_query(_build_query(GUARD_FUNCS))
    auth_raw  = await _run_cpg_query(_build_query(AUTH_FUNCS))
    err_raw   = await _run_cpg_query(_build_query(ERROR_FUNCS))

    def _parse(raw: dict[str, Any], funcs: list[str]) -> list[str]:
        if not raw.get("success"):
            return []
        parsed = raw.get("parsed")
        if isinstance(parsed, list):
            matched: list[str] = []
            target_names = set(funcs)
            for item in parsed:
                if not isinstance(item, dict):
                    continue
                name = item.get("name")
                line = item.get("line", -1)
                if isinstance(name, str) and name in target_names:
                    matched.append(f"{name} @ line {line}")
            return matched
        return []

    san_calls   = _parse(san_raw,   SANITIZER_FUNCS)
    guard_calls = _parse(guard_raw, GUARD_FUNCS)
    auth_calls  = _parse(auth_raw,  AUTH_FUNCS)
    err_calls   = _parse(err_raw,   ERROR_FUNCS)

    protection_summary: dict[str, Any] | None = None
    if sink_kind and sink_kind in JOERN_SINKS and JOERN_SOURCES:
        sink_regex = JOERN_SINKS[sink_kind].get("regex", "")
        query = _get_taint_builder().build_protection_query(
            sink_name=sink_kind,
            sink_regex=sink_regex,
            sanitizers=SANITIZER_FUNCS,
            guards=GUARD_FUNCS,
            file_path=file_path,
            function_name=function_name,
        )
        prot_raw    = await _run_cpg_query(query, ensure_overlays=True)
        prot_parsed = prot_raw.get("parsed", {})

        if (
            prot_raw.get("success")
            and isinstance(prot_parsed, dict)
            and "raw_stdout" not in prot_parsed
        ):
            matched_sanitizers = []
            for detail in prot_parsed.get("details", []):
                if isinstance(detail, dict):
                    matched_sanitizers.extend(detail.get("matched_sanitizers", []))

            guard_dominance = prot_parsed.get("guard_dominance", {})

            protection_summary = {
                "sink_kind":        sink_kind,
                "total_flows":      prot_parsed.get("total_flows", 0),
                "protected_flows":  prot_parsed.get("protected_flows", 0),
                "is_sanitized":     prot_parsed.get("protected_flows", 0) > 0,
                "matched_sanitizers": matched_sanitizers,
                "case_stats": prot_parsed.get("case_stats", []),
                "guard_dominance": guard_dominance,
            }
        else:
            protection_summary = {
                "sink_kind": sink_kind,
                "error":     _fmt_executor(prot_raw),
            }

    result = {
        "file_path":      file_path,
        "function":       function_name,
        "has_sanitizer":  len(san_calls) > 0,
        "has_guard":      len(guard_calls) > 0,
        "has_auth_check": len(auth_calls) > 0,
        "has_error_exit": len(err_calls) > 0,
        "found_calls": {
            "sanitizers":  san_calls,
            "guards":      guard_calls,
            "auth_checks": auth_calls,
            "error_exits": err_calls,
        },
        "protection_analysis": protection_summary,
    }
    await _cache.set_json(cache_key, result, project=project, revision=revision)
    return json.dumps(result, ensure_ascii=False, indent=2)

# ──────────────────────────────────────────────────────────────────────────────
# Tool 등록
# ──────────────────────────────────────────────────────────────────────────────


def register(mcp: FastMCP) -> None:
    """tool 등록 — server.py 에서 mcp 인스턴스를 받아 호출."""
    mcp.tool()(get_cpg_summary)
    mcp.tool()(find_dataflow)
    mcp.tool()(find_sanitizer_or_guard)
