#!/usr/bin/env python3
"""
extract_ast.py  —  compile_commands.json 기반 C/C++ 함수 정의 위치 + 참조 파일 목록 추출.

컨테이너 안에서 ClangAstRunner 가 subprocess 로 호출한다.

Usage:
    python3 extract_ast.py <compile_commands.json> [includeable_path ...]

    includeable_path  컴파일 단위를 이름(서픽스 일치)으로 제한.
                      생략하면 compile_commands.json 의 모든 파일을 파싱.

Stdout (JSON, 한 줄):
    [
        {                              # def_sites  : file → [{name, line, end_line, col}]
            "src/main.c": [
                {"name": "main", "display_name": "main(int, char **)",
                 "line": 10, "col": 1, "end_line": 30},
                ...
            ],
            ...
        },
        [                              # referenced_files : 실제 컴파일/include 된 파일 경로
            "src/main.c",
            "include/util.h",
            ...
        ]
    ]
"""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path
from typing import Any


# ── libclang import ───────────────────────────────────────────────────────────
try:
    import clang.cindex as cindex
except ImportError:
    print(
        "[ERROR] libclang Python 바인딩을 찾을 수 없습니다.\n"
        "  pip3 install libclang  을 실행하거나 Dockerfile 에 추가하세요.",
        file=sys.stderr,
    )
    sys.exit(1)

# 함수/메서드 정의로 간주할 cursor 종류
_DEF_KINDS = {
    cindex.CursorKind.FUNCTION_DECL,
    cindex.CursorKind.CXX_METHOD,
    cindex.CursorKind.CONSTRUCTOR,
    cindex.CursorKind.DESTRUCTOR,
    cindex.CursorKind.FUNCTION_TEMPLATE,
    cindex.CursorKind.CONVERSION_FUNCTION,
}


# ── compile_commands 파싱 ─────────────────────────────────────────────────────

def load_compile_commands(path: Path) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _extract_flags(entry: dict[str, Any]) -> tuple[str, list[str]]:
    """
    compile_commands.json 의 한 항목에서 (source_file, compile_flags) 를 추출.

    -o, -MF, -c 등 클랭 파싱에 불필요한 플래그는 제거한다.
    """
    source_file: str = entry["file"]

    if "arguments" in entry:
        raw_args: list[str] = entry["arguments"]
    elif "command" in entry:
        raw_args = shlex.split(entry["command"])
    else:
        return source_file, []

    skip_value_flags = {"-o", "-MF", "-MT", "-MQ", "-isystem"}
    skip_prefix_flags = ("-o", "-MF")
    skip_solo_flags = {"-c", "-E", "-S", "-MD", "-MMD", "-MP"}

    flags: list[str] = []
    skip_next = False

    for i, arg in enumerate(raw_args):
        if skip_next:
            skip_next = False
            continue
        if i == 0:          # 컴파일러 실행 파일 자체
            continue
        if arg == source_file:
            continue
        if arg in skip_solo_flags:
            continue
        if arg in skip_value_flags:
            skip_next = True
            continue
        if any(arg.startswith(p) and len(arg) > len(p) for p in skip_prefix_flags):
            continue
        flags.append(arg)

    return source_file, flags


# ── AST 파싱 ──────────────────────────────────────────────────────────────────

def _parse_one(
    source_file: str,
    flags: list[str],
    index: cindex.Index,
) -> tuple[list[dict[str, Any]], set[str]]:
    """
    단일 소스 파일을 libclang 으로 파싱.

    Returns:
        (def_sites_list, referenced_files_set)
        def_sites_list   : [{name, display_name, line, col, end_line}, ...]
        referenced_files : include 된 모든 파일 경로 + 소스 파일 자체
    """
    try:
        tu = index.parse(
            source_file,
            args=flags,
            options=(
                cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
                | cindex.TranslationUnit.PARSE_SKIP_FUNCTION_BODIES  # 속도용 (정의 위치는 여전히 수집)
            ),
        )
    except Exception as exc:
        print(f"[WARN] parse failed: {source_file} — {exc}", file=sys.stderr)
        return [], set()

    # 진단 오류가 있어도 계속 진행 (경고만 출력)
    fatal = [d for d in tu.diagnostics if d.severity >= cindex.Diagnostic.Error]
    if fatal:
        print(
            f"[WARN] {len(fatal)} error(s) in {source_file} "
            f"(예: {fatal[0].spelling[:80]})",
            file=sys.stderr,
        )

    # ── referenced files (source + all transitive includes) ──────────────────
    referenced: set[str] = {source_file}
    for inc in tu.get_includes():
        if inc.include:
            referenced.add(str(inc.include.name))

    # ── function definition sites ─────────────────────────────────────────────
    source_path = Path(source_file).resolve()
    def_sites: list[dict[str, Any]] = []

    def _visit(cursor: cindex.Cursor) -> None:
        if cursor.kind in _DEF_KINDS and cursor.is_definition():
            loc = cursor.location
            if loc.file and Path(str(loc.file.name)).resolve() == source_path:
                def_sites.append(
                    {
                        "name":         cursor.spelling,
                        "display_name": cursor.displayname,
                        "line":         loc.line,
                        "col":          loc.column,
                        "end_line":     cursor.extent.end.line,
                    }
                )
        for child in cursor.get_children():
            _visit(child)

    _visit(tu.cursor)
    return def_sites, referenced


# ── 필터링 헬퍼 ───────────────────────────────────────────────────────────────

def _matches_includeable(source_file: str, include_set: set[str]) -> bool:
    """includeable_paths 중 하나라도 source_file 경로의 suffix 와 일치하면 True."""
    p = Path(source_file)
    for inc in include_set:
        inc_p = Path(inc)
        # 절대경로 / 상대경로 / 파일명 모두 허용
        if p == inc_p or p.name == inc_p.name or str(p).endswith(inc):
            return True
    return False


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(
        description="compile_commands.json 을 libclang 으로 파싱하여 함수 정의 위치와 참조 파일을 추출."
    )
    ap.add_argument("compile_commands", type=Path, help="compile_commands.json 경로")
    ap.add_argument(
        "includeable",
        nargs="*",
        help="파싱 대상 파일 필터 (파일명/접미사 일치). 생략하면 전체 파싱.",
    )
    ap.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="결과 JSON 저장 경로. 생략하면 stdout 출력.",
    )
    args = ap.parse_args()

    if not args.compile_commands.exists():
        print(f"[ERROR] 파일 없음: {args.compile_commands}", file=sys.stderr)
        sys.exit(1)

    entries = load_compile_commands(args.compile_commands)
    include_set = set(args.includeable)
    index = cindex.Index.create()

    all_def_sites: dict[str, list[dict[str, Any]]] = {}
    all_referenced: set[str] = set()

    for entry in entries:
        source_file, flags = _extract_flags(entry)

        if include_set and not _matches_includeable(source_file, include_set):
            continue

        print(f"[*] {source_file}", file=sys.stderr)

        defs, referenced = _parse_one(source_file, flags, index)

        if defs:
            all_def_sites[source_file] = defs
        all_referenced |= referenced

    result = [all_def_sites, sorted(all_referenced)]
    output_json = json.dumps(result, ensure_ascii=False, indent=2)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output_json, encoding="utf-8")
        print(f"[+] 저장 완료: {args.output}", file=sys.stderr)
    else:
        print(output_json)


if __name__ == "__main__":
    main()
