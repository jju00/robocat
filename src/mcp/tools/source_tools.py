"""
Tools: source reader
====================
• mcp__nld__read_source_context  — line-range / function-body snippet
• mcp__nld__find_references      — ripgrep 기반 심볼·패턴 참조 검색
• mcp__nld__read_definition      — ctags + tree-sitter 함수 정의 추출
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP


# ─────────────────────────────────────────────────────────────
# Tool instructions
# ─────────────────────────────────────────────────────────────

TOOL_INSTRUCTIONS: dict[str, str] = {
    "read_source_context": (
        "특정 함수 전체 또는 라인 주변 코드 snippet을 읽는다.\n"
        "취약점 분석 기본 원칙:\n"
        "- 먼저 CPG 도구(get_cpg_summary, find_dataflow, find_sanitizer_or_guard)로\n"
        "  call graph, source→sink, guard 정보를 확인한다.\n"
        "- 그 다음 CPG에서 식별된 line/callsite 근방만 read_source_context로 읽는다.\n"
        "- 전체 파일을 무차별로 읽지 말고, 필요한 evidence line 위주로 최소 호출한다.\n\n"
        "소스 확인 시 아래 8가지 우선순위로 라인을 좁혀서 호출한다.\n\n"
        "1. sink 라인\n"
        "   - memcpy/memmove/strcpy/snprintf, malloc/calloc/realloc, free,\n"
        "     배열 인덱싱, 포인터 역참조 라인\n\n"
        "2. sink의 크기/인덱스 식 정의 지점\n"
        "   - len/size/count/index/offset가 마지막으로 대입·변환된 라인\n"
        "   - 특히 signed→unsigned, +,-,* 계산식\n\n"
        "3. 할당-사용-해제 체인\n"
        "   - 같은 포인터에 대한 alloc site, free site, post-free use 라인\n\n"
        "4. 입력 유입 지점(source)\n"
        "   - 함수 인자, 파일/네트워크 read, 파서 결과가 변수로 들어오는 첫 라인\n\n"
        "5. 검증/가드 지점\n"
        "   - bounds check, null check, range check가 실제로 sink 이전 경로를\n"
        "     지배하는지 확인할 분기 라인\n\n"
        "6. 콜 경계(최소)\n"
        "   - 현재 함수의 direct caller 1단계 (인자 신뢰도 확인)\n"
        "   - direct callee 1단계 (사이즈 계산/메모리 연산 위임 여부 확인)\n\n"
        "7. 구조체 필드 정의\n"
        "   - sink/source에 쓰인 핵심 필드의 선언부 (타입, 폭, signedness, 버퍼 길이 의미)\n\n"
        "8. 에러/예외 경로\n"
        "   - 실패 시 조기 반환·cleanup 경로에서 double free/UAF 가능성 있는 분기\n\n"
        "호출 요령:\n"
        "- function_name: 대상 함수 전체 문맥 확인이 필요할 때 사용\n"
        "- line+before/after: CPG가 지목한 특정 sink/guard/source 라인 근방을 정밀 확인할 때 사용"
    ),
    "find_references": (
        "심볼/패턴의 사용처(호출부, 대입부, 전파 지점)를 ripgrep으로 빠르게 찾는다.\n"
        "다음 상황에서 우선 사용한다:\n"
        "- call graph에서 caller/callee가 부족하거나 비어 있을 때\n"
        "- 함수 포인터/매크로/플랫폼 분기로 호출 관계가 흐려질 때\n"
        "- source→sink가 함수 경계를 넘어 전파되는지 확인할 때\n\n"
        "사용 지침:\n"
        "- symbol_or_pattern에는 함수명/필드명/정규식을 넣는다.\n"
        "- max_results는 20~100 사이로 시작하고, truncated=true면 범위를 좁혀 재호출한다.\n"
        "- dir를 지정해 검색 범위를 분석 대상 모듈로 제한하면 노이즈가 줄어든다."
    ),
    "read_definition": (
        "심볼의 정의(함수/타입/필드 선언)를 ctags로 찾고, 필요 시 본문까지 추출한다.\n"
        "다음 상황에서 사용한다:\n"
        "- callee 내부 구현을 봐야 size 계산/메모리 연산 위임 여부를 판단할 때\n"
        "- 구조체/typedef 선언을 확인해 버퍼 크기·signedness를 검증할 때\n"
        "- 동일 이름 심볼이 여러 파일에 있어 정확한 정의를 특정해야 할 때\n\n"
        "사용 지침:\n"
        "- file 인자로 후보 파일을 제한해 같은 이름의 중복 정의를 줄인다.\n"
        "- include_body=False는 선언/시그니처만 빠르게 확인할 때 사용한다.\n"
        "- include_body=True는 sink 계산식/포인터 수명 로직까지 검증해야 할 때만 사용한다."
    ),
}


# ─────────────────────────────────────────────────────────────
# tree-sitter (optional — 미설치 시 brace-counting fallback)
# ─────────────────────────────────────────────────────────────

_TS_AVAILABLE = False
_ts_parser: Any = None

try:
    import tree_sitter_c as _tsc
    from tree_sitter import Language, Parser as _TSParser

    _ts_parser = _TSParser(Language(_tsc.language()))
    _TS_AVAILABLE = True
except Exception:
    pass


# ─────────────────────────────────────────────────────────────
# util
# ─────────────────────────────────────────────────────────────

def _json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


def _source_root() -> Path:
    env = os.getenv("HOST_SOURCE_ROOT")
    return Path(env) if env else Path.cwd()


def _resolve_file(file_path: str) -> Path:
    p = Path(file_path)
    if p.exists():
        return p.resolve()

    container_root = os.getenv("CONTAINER_SOURCE_ROOT", "/app/source")
    host_root_env = os.getenv("HOST_SOURCE_ROOT")

    if file_path.startswith(container_root) and host_root_env:
        rel = Path(file_path).relative_to(container_root)
        candidate = Path(host_root_env) / rel
        if candidate.exists():
            return candidate.resolve()

    if host_root_env:
        candidate = Path(host_root_env) / file_path
        if candidate.exists():
            return candidate.resolve()

    raise FileNotFoundError(f"file not found: {file_path}")


def _extract_lines(text: str, start: int, end: int) -> str:
    lines = text.splitlines()
    return "\n".join(lines[max(0, start - 1) : min(len(lines), end)])


def _line_no_from_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _line_snippet(text: str, line_no: int) -> str:
    lines = text.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1]
    return ""


def _context_snippet(text: str, line_no: int, before: int = 2, after: int = 2) -> str:
    start = max(1, line_no - before)
    end = line_no + after
    return _extract_lines(text, start, end)


# ─────────────────────────────────────────────────────────────
# tree-sitter helpers
# ─────────────────────────────────────────────────────────────

def _ts_func_name(node: Any) -> str | None:
    """function_definition 노드에서 함수 이름을 추출한다.

    일반형:  int  func(...)          → function_declarator > identifier
    포인터형: char *func(...)         → pointer_declarator > function_declarator > identifier
    """
    for child in node.children:
        if child.type == "function_declarator":
            for sub in child.children:
                if sub.type == "identifier":
                    return sub.text.decode("utf-8", errors="replace")
        elif child.type == "pointer_declarator":
            for sub in child.children:
                if sub.type == "function_declarator":
                    for subsub in sub.children:
                        if subsub.type == "identifier":
                            return subsub.text.decode("utf-8", errors="replace")
    return None


def _ts_walk(node: Any, func_name: str | None, target_line: int | None):
    """AST를 DFS로 탐색해 조건에 맞는 function_definition의 (start, end) 반환.

    func_name   지정 시: 이름이 일치하는 함수
    target_line 지정 시: 해당 줄을 포함하는 함수
    (둘 다 지정하면 AND 조건)
    """
    if node.type == "function_definition":
        sl = node.start_point[0] + 1
        el = node.end_point[0] + 1
        name_ok = (func_name is None) or (_ts_func_name(node) == func_name)
        line_ok = (target_line is None) or (sl <= target_line <= el)
        if name_ok and line_ok:
            return (sl, el)
    for child in node.children:
        result = _ts_walk(child, func_name, target_line)
        if result:
            return result
    return None


def _ts_bounds_by_name(path: Path, func_name: str) -> tuple[int, int] | None:
    if not _TS_AVAILABLE or _ts_parser is None:
        return None
    tree = _ts_parser.parse(path.read_bytes())
    return _ts_walk(tree.root_node, func_name=func_name, target_line=None)


def _ts_bounds_by_line(path: Path, target_line: int) -> tuple[int, int] | None:
    if not _TS_AVAILABLE or _ts_parser is None:
        return None
    tree = _ts_parser.parse(path.read_bytes())
    return _ts_walk(tree.root_node, func_name=None, target_line=target_line)


def _brace_bounds(text: str, func_name: str) -> tuple[int, int] | None:
    """tree-sitter 미설치 시 brace-counting fallback."""
    pattern = re.compile(rf"\b{re.escape(func_name)}\b\s*\(")
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if not pattern.search(line):
            continue
        brace, started = 0, False
        for j in range(i, len(lines)):
            brace += lines[j].count("{")
            if "{" in lines[j]:
                started = True
            brace -= lines[j].count("}")
            if started and brace <= 0:
                return (i + 1, j + 1)
    return None


# ─────────────────────────────────────────────────────────────
# ctags helpers
# ─────────────────────────────────────────────────────────────

@dataclass
class _CtagsEntry:
    name: str
    file: str
    line: int
    kind: str
    language: str
    signature: str
    scope: str


def _ctags_search(
    symbol: str,
    search_root: Path,
    file_filter: Optional[str] = None,
) -> list[_CtagsEntry]:
    """Universal Ctags로 symbol 정의를 검색한다.

    1단계: rg --files-with-matches 로 candidate 파일 탐색 (빠름)
    2단계: 각 candidate 파일에 ctags --output-format=json 실행
    """
    ctags_bin = shutil.which("ctags")
    if not ctags_bin:
        return []

    # ── candidate 파일 결정 ───────────────────────────────────
    if file_filter and Path(file_filter).is_file():
        candidate_files: list[Path] = [Path(file_filter)]
    else:
        target_dir = Path(file_filter) if file_filter else search_root
        candidate_files = _rg_files_with_matches(symbol, target_dir)
        if not candidate_files:
            return []

    # ── 파일별 ctags 실행 ─────────────────────────────────────
    entries: list[_CtagsEntry] = []
    for target in candidate_files[:20]:
        try:
            result = subprocess.run(
                [ctags_bin, "--output-format=json", "--fields=+nSs", str(target)],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except Exception:
            continue

        for raw in result.stdout.splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if obj.get("name") != symbol:
                continue
            entries.append(
                _CtagsEntry(
                    name=obj.get("name", ""),
                    file=obj.get("path", ""),
                    line=int(obj.get("line", 0)),
                    kind=obj.get("kind", ""),
                    language=obj.get("language", ""),
                    signature=obj.get("signature", ""),
                    scope=obj.get("scope", ""),
                )
            )

    return entries


def _rg_files_with_matches(pattern: str, search_dir: Path) -> list[Path]:
    """rg --files-with-matches 로 pattern이 등장하는 파일 목록 반환."""
    rg_bin = shutil.which("rg")
    if not rg_bin:
        return []
    try:
        proc = subprocess.run(
            [rg_bin, "--files-with-matches", "-w", pattern, str(search_dir)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return [Path(f) for f in proc.stdout.splitlines() if f.strip()]
    except Exception:
        return []


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

    - function_name → tree-sitter로 함수 전체 추출 (fallback: brace counting)
    - line          → 주변 before/after 라인 snippet

    Args:
        file_path:     대상 파일 경로 (CPG 내부 경로 또는 호스트 절대경로)
        line:          중심 라인 번호 (function_name 미지정 시 필수)
        before:        line 기준 앞 라인 수 (기본 30)
        after:         line 기준 뒤 라인 수 (기본 30)
        function_name: 추출할 함수 이름 (지정 시 함수 전체 반환)
    """
    try:
        path = _resolve_file(file_path)
    except Exception as e:
        return _json({"error": str(e)})

    text = path.read_text(errors="ignore")

    # ── function_name 기준 ──────────────────────────────────
    if function_name:
        bounds = _ts_bounds_by_name(path, function_name) or _brace_bounds(text, function_name)
        if bounds is None:
            return _json({"error": f"function not found: {function_name}", "file_path": file_path})
        start_line, end_line = bounds
        return _json({
            "file_path": file_path,
            "start_line": start_line,
            "end_line": end_line,
            "code": _extract_lines(text, start_line, end_line),
        })

    # ── line 기준 ───────────────────────────────────────────
    if line is None:
        return _json({"error": "line or function_name required"})

    try:
        line = int(line)
    except (TypeError, ValueError):
        return _json({"error": f"invalid line: {line}"})

    start = max(1, line - before)
    end = line + after
    return _json({
        "file_path": file_path,
        "start_line": start,
        "end_line": end,
        "code": _extract_lines(text, start, end),
    })


# ─────────────────────────────────────────────────────────────
# Tool 2: find_references
# ─────────────────────────────────────────────────────────────

def mcp__nld__find_references(
    symbol_or_pattern: str,
    dir: Optional[str] = None,
    max_results: int = 50,
) -> str:
    """
    ripgrep으로 심볼·패턴 참조를 검색한다.

    Args:
        symbol_or_pattern: 검색할 심볼 이름 또는 정규식 패턴
        dir:               검색 디렉토리 (없으면 HOST_SOURCE_ROOT)
        max_results:       반환할 최대 결과 수

    Returns:
        JSON {"references": [{file, line, snippet}], "total": N, "truncated": bool}
    """
    rg_bin = shutil.which("rg")
    if not rg_bin:
        return _json({"error": "ripgrep(rg) not found in PATH"})

    search_dir = str(Path(dir).resolve() if dir else _source_root())

    try:
        proc = subprocess.run(
            [rg_bin, "--json", "-e", symbol_or_pattern, search_dir],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except subprocess.TimeoutExpired:
        return _json({"error": "rg timed out"})
    except FileNotFoundError:
        return _json({"error": "rg not found"})

    matches: list[dict] = []
    for raw in proc.stdout.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if obj.get("type") != "match":
            continue

        data = obj["data"]
        matches.append({
            "file": data["path"]["text"],
            "line": data["line_number"],
            "snippet": data["lines"]["text"].rstrip("\n"),
        })
        if len(matches) >= max_results:
            break

    return _json({
        "references": matches,
        "total": len(matches),
        "truncated": len(matches) >= max_results,
    })


# ─────────────────────────────────────────────────────────────
# Tool 3: read_definition
# ─────────────────────────────────────────────────────────────

def mcp__nld__read_definition(
    symbol: str,
    file: Optional[str] = None,
    include_body: bool = True,
) -> str:
    """
    ctags로 심볼 정의를 찾고, tree-sitter로 함수 본문을 추출한다.

    Args:
        symbol:       정의를 찾을 심볼 (함수명, 타입명 등)
        file:         특정 파일로 검색 범위 제한 (없으면 HOST_SOURCE_ROOT 전체)
        include_body: True면 함수 본문 코드 포함

    Returns:
        JSON {"symbol": str, "definitions": [{file, line, kind, signature, scope, body?}]}
    """
    entries = _ctags_search(symbol, _source_root(), file_filter=file)

    if not entries:
        return _json({"symbol": symbol, "definitions": [], "note": "ctags: no match"})

    results: list[dict] = []
    for e in entries[:10]:
        item: dict = {
            "file": e.file,
            "line": e.line,
            "kind": e.kind,
            "language": e.language,
            "signature": e.signature,
            "scope": e.scope,
        }

        if include_body:
            try:
                src_path = _resolve_file(e.file)
                bounds = _ts_bounds_by_line(src_path, e.line)
                if bounds:
                    text = src_path.read_text(errors="ignore")
                    item["body"] = _extract_lines(text, bounds[0], bounds[1])
                    item["start_line"] = bounds[0]
                    item["end_line"] = bounds[1]
            except Exception as exc:
                item["body_error"] = str(exc)

        results.append(item)

    return _json({"symbol": symbol, "definitions": results})


# ─────────────────────────────────────────────────────────────
# Tool 4: map_vuln_context
# ─────────────────────────────────────────────────────────────

_SINK_REGEXES: dict[str, str] = {
    "copy": r"\b(memcpy|memmove|strcpy|strncpy|strcat|strncat|snprintf|vsnprintf)\s*\(",
    "alloc": r"\b(malloc|calloc|realloc|strdup|strndup)\s*\(",
    "free": r"\bfree\s*\(",
    "index": r"\b[A-Za-z_]\w*\s*\[[^\]]+\]",
    "deref": r"(\-\>|(?<!\.)\.[A-Za-z_]\w*)",
}

_SOURCE_CALLS = r"\b(read|recv|fread|getenv|strtol|strtoul|atoi|atol|parse|decode)\s*\("
_GUARD_HINT = r"\b(if|while)\b.*(len|size|count|idx|index|offset|NULL|!=\s*0|>\s*0|<\s*)"
_ERROR_HINT = r"\b(return|goto)\b.*(ERR|FAIL|FATAL|WARN|error|cleanup)|\b(abort|exit|die)\s*\("
_SIZE_HINT = re.compile(r"\b(len|size|count|idx|index|offset|cap|num)\w*\b", re.IGNORECASE)
_KEYWORDS = {
    "if", "for", "while", "switch", "return", "sizeof",
}


def _extract_param_names(fn_code: str) -> list[str]:
    header = fn_code.split("{", 1)[0]
    m = re.search(r"\((.*)\)", header, flags=re.DOTALL)
    if not m:
        return []
    params = []
    for raw in m.group(1).split(","):
        part = raw.strip()
        if not part or part == "void":
            continue
        names = re.findall(r"([A-Za-z_]\w*)", part)
        if names:
            params.append(names[-1])
    return params


def _collect_calls(fn_code: str) -> list[str]:
    names: list[str] = []
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", fn_code):
        name = m.group(1)
        if name in _KEYWORDS:
            continue
        names.append(name)
    uniq = []
    seen = set()
    for n in names:
        if n in seen:
            continue
        seen.add(n)
        uniq.append(n)
    return uniq


def _extract_free_var(line: str) -> str | None:
    m = re.search(r"\bfree\s*\(\s*([A-Za-z_]\w*)", line)
    if m:
        return m.group(1)
    return None


def mcp__nld__map_vuln_context(
    file_path: str,
    function_name: str,
    include_call_definitions: bool = False,
    max_call_definitions: int = 8,
) -> str:
    """
    취약점 탐지에 필요한 핵심 슬라이스만 함수 단위로 매핑한다.

    반환 슬라이스:
    - sinks / size_or_index_defs / alloc_free_use / sources
    - guards / error_paths / call_boundary / struct_field_usage
    """
    try:
        path = _resolve_file(file_path)
    except Exception as e:
        return _json({"error": str(e)})

    full_text = path.read_text(errors="ignore")
    bounds = _ts_bounds_by_name(path, function_name) or _brace_bounds(full_text, function_name)
    if not bounds:
        return _json({"error": f"function not found: {function_name}", "file_path": file_path})

    fn_start, fn_end = bounds
    fn_code = _extract_lines(full_text, fn_start, fn_end)
    fn_lines = fn_code.splitlines()

    # 1) sink lines
    sinks: list[dict[str, Any]] = []
    for kind, pat in _SINK_REGEXES.items():
        for m in re.finditer(pat, fn_code):
            local_line = _line_no_from_offset(fn_code, m.start())
            abs_line = fn_start + local_line - 1
            sinks.append({
                "kind": kind,
                "line": abs_line,
                "snippet": _line_snippet(fn_code, local_line).strip(),
                "context": _context_snippet(full_text, abs_line),
            })
    sinks.sort(key=lambda x: x["line"])

    # 2) size/index defs near sink variables
    tracked_vars = set()
    for entry in sinks:
        for var in _SIZE_HINT.findall(entry["snippet"]):
            tracked_vars.add(var)
    size_defs: list[dict[str, Any]] = []
    for idx, line in enumerate(fn_lines, start=1):
        if "=" not in line and "+=" not in line and "-=" not in line:
            continue
        if tracked_vars:
            if not any(re.search(rf"\b{re.escape(v)}\b", line) for v in tracked_vars):
                continue
        elif not _SIZE_HINT.search(line):
            continue
        abs_line = fn_start + idx - 1
        size_defs.append({
            "line": abs_line,
            "snippet": line.strip(),
        })

    # 3) alloc/free/use chain (intra-function heuristic)
    alloc_sites: list[dict[str, Any]] = []
    free_sites: list[dict[str, Any]] = []
    post_free_use: list[dict[str, Any]] = []
    for idx, line in enumerate(fn_lines, start=1):
        abs_line = fn_start + idx - 1
        if re.search(_SINK_REGEXES["alloc"], line):
            alloc_sites.append({"line": abs_line, "snippet": line.strip()})
        if re.search(_SINK_REGEXES["free"], line):
            free_sites.append({"line": abs_line, "snippet": line.strip()})

    for free_entry in free_sites:
        var = _extract_free_var(free_entry["snippet"])
        if not var:
            continue
        for idx, line in enumerate(fn_lines, start=1):
            abs_line = fn_start + idx - 1
            if abs_line <= free_entry["line"]:
                continue
            if re.search(rf"\b{re.escape(var)}\b", line) and not re.search(
                rf"\b{re.escape(var)}\b\s*=\s*NULL", line
            ):
                post_free_use.append({
                    "var": var,
                    "line": abs_line,
                    "snippet": line.strip(),
                })

    # 4) sources (params + common input calls)
    param_names = _extract_param_names(fn_code)
    source_calls: list[dict[str, Any]] = []
    for idx, line in enumerate(fn_lines, start=1):
        if re.search(_SOURCE_CALLS, line):
            source_calls.append({
                "line": fn_start + idx - 1,
                "snippet": line.strip(),
            })
    sources = {
        "params": param_names,
        "input_calls": source_calls,
    }

    # 5) guards
    guard_lines: list[dict[str, Any]] = []
    for idx, line in enumerate(fn_lines, start=1):
        if re.search(_GUARD_HINT, line):
            guard_lines.append({
                "line": fn_start + idx - 1,
                "snippet": line.strip(),
            })

    # 6) error paths
    error_lines: list[dict[str, Any]] = []
    for idx, line in enumerate(fn_lines, start=1):
        if re.search(_ERROR_HINT, line):
            error_lines.append({
                "line": fn_start + idx - 1,
                "snippet": line.strip(),
            })

    # 7) call boundary (direct calls + optional definitions)
    callees = _collect_calls(fn_code)
    call_boundary: dict[str, Any] = {
        "direct_callees": callees,
        "direct_callee_count": len(callees),
        "definitions": [],
    }
    if include_call_definitions:
        defs: list[dict[str, Any]] = []
        for callee in callees[: max(1, max_call_definitions)]:
            for e in _ctags_search(callee, _source_root(), file_filter=file_path)[:1]:
                defs.append({
                    "symbol": callee,
                    "file": e.file,
                    "line": e.line,
                    "kind": e.kind,
                    "signature": e.signature,
                    "scope": e.scope,
                })
        call_boundary["definitions"] = defs

    # 8) struct field usage in function
    field_hits: list[dict[str, Any]] = []
    for idx, line in enumerate(fn_lines, start=1):
        for m in re.finditer(r"(?:->|\.)\s*([A-Za-z_]\w*)", line):
            field = m.group(1)
            field_hits.append({
                "field": field,
                "line": fn_start + idx - 1,
                "snippet": line.strip(),
            })

    return _json({
        "file_path": file_path,
        "function_name": function_name,
        "function_bounds": {"start_line": fn_start, "end_line": fn_end},
        "function_code": fn_code,
        "slices": {
            "sinks": sinks,
            "size_or_index_defs": size_defs,
            "alloc_free_use": {
                "alloc_sites": alloc_sites,
                "free_sites": free_sites,
                "post_free_use": post_free_use,
            },
            "sources": sources,
            "guards": guard_lines,
            "error_paths": error_lines,
            "call_boundary": call_boundary,
            "struct_field_usage": field_hits,
        },
    })


# ─────────────────────────────────────────────────────────────
# register
# ─────────────────────────────────────────────────────────────

def register(mcp: FastMCP) -> None:
    mcp.tool()(mcp__nld__read_source_context)
    mcp.tool()(mcp__nld__find_references)
    mcp.tool()(mcp__nld__read_definition)
    mcp.tool()(mcp__nld__map_vuln_context)
