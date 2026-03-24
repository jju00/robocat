"""
clang_ast.py  —  extract_ast.py 가 생성한 ast_result.json 을 읽는 유틸.

Shell 파이프라인이 Docker 안에서 extract_ast.py 를 실행하고
ast_result.json 을 workspace 에 저장한 뒤, 이 모듈이 파일을 로드한다.

Expected file format (extract_ast.py 출력):
    [
        {                              # def_sites
            "src/main.c": [
                {"name": "func", "display_name": "func(int)",
                 "line": 10, "col": 1, "end_line": 30},
                ...
            ]
        },
        ["src/main.c", "include/util.h", ...]   # referenced_files
    ]
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


AstDefSites = dict[str, list[dict[str, Any]]]   # file → [{name, line, ...}]


def load_ast_result(path: str | Path) -> tuple[AstDefSites, set[str]]:
    """
    extract_ast.py 가 생성한 ast_result.json 을 읽어 반환.

    Args:
        path: ast_result.json 경로

    Returns:
        (def_sites, referenced_files)
        def_sites        : {상대경로 파일명: [{name, display_name, line, col, end_line}]}
        referenced_files : 컴파일/include 된 모든 파일 경로 집합
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"ast_result.json not found: {path}")

    with open(path, encoding="utf-8") as f:
        parsed = json.load(f)

    if not isinstance(parsed, list) or len(parsed) != 2:
        raise ValueError(f"ast_result.json 형식 오류: 길이 2 배열이어야 합니다. ({path})")

    raw_def_sites, raw_referenced = parsed

    if not isinstance(raw_def_sites, dict):
        raise ValueError("ast_result.json[0] 은 dict[file → defs] 이어야 합니다.")
    if not isinstance(raw_referenced, list):
        raise ValueError("ast_result.json[1] 은 list[file_path] 이어야 합니다.")

    return raw_def_sites, set(raw_referenced)
