"""NLD MCP — 환경 설정 / 상수 모음
====================================
• .env 로드
• sys.path 설정  (scripts/joern 포함)
• runner config / rules JSON 로드
• 모든 JOERN_* / RETRIEVER_* 상수 공개
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

# ──────────────────────────────────────────────────────────────────────────────
# 경로 설정 (모듈 최초 import 시 1회 실행)
# ──────────────────────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parents[2]   # src/mcp/config.py → NLD/
load_dotenv(ROOT / ".env")
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts" / "joern"))

CONFIGS_DIR = ROOT / "scripts" / "joern" / "runners" / "configs"
RULES_DIR   = ROOT / "scripts" / "joern" / "runners" / "rules"

# ──────────────────────────────────────────────────────────────────────────────
# Retriever 경로  (모듈 로드 후 _resolve_data_paths() 에서 최종 결정)
# ──────────────────────────────────────────────────────────────────────────────

def _resolve_data_paths(runner_cfg: dict[str, Any]) -> tuple[Path, Path]:
    """data/{LANGUAGE}/{TARGET}/... 경로를 결정한다.

    우선순위:
      1. 환경변수 RETRIEVER_OUTPUT_PATH / DIFF_RETRIEVER_PATH 명시
      2. runner config의 language + JOERN_CONFIG(target)으로 자동 조합
         data/{language.upper()}/{target}/retriever/retriever_output_top1.json
         data/{language.upper()}/{target}/diff/diff_retriever.json
      3. 레거시 fallback
         data/retriever/retriever_output.json
         data/diff/diff_retriever.json
    """
    language = runner_cfg.get("project", {}).get("language", "")
    target   = os.getenv("JOERN_CONFIG", "").split(".")[0]   # 확장자 제거

    if env := os.getenv("RETRIEVER_OUTPUT_PATH"):
        retriever_path = Path(env)
    elif language and target:
        retriever_path = ROOT / "data" / language.upper() / target / "retriever" / "retriever_output_top1.json"
    else:
        retriever_path = ROOT / "data" / "retriever" / "retriever_output.json"

    if env := os.getenv("DIFF_RETRIEVER_PATH"):
        diff_path = Path(env)
    elif language and target:
        diff_path = ROOT / "data" / language.upper() / target / "diff" / "diff_retriever.json"
    else:
        diff_path = ROOT / "data" / "diff" / "diff_retriever.json"

    return retriever_path, diff_path

# ──────────────────────────────────────────────────────────────────────────────
# Joern 연결
# ──────────────────────────────────────────────────────────────────────────────

JOERN_HOST = os.getenv("JOERN_HOST", "localhost")
JOERN_PORT = int(os.getenv("JOERN_PORT", "9000"))

# ──────────────────────────────────────────────────────────────────────────────
# Runner config / rules 로더
# ──────────────────────────────────────────────────────────────────────────────


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
        path = CONFIGS_DIR / (name if "." in name else f"{name}.json")

    if not path.exists():
        print(f"[NLD-MCP] WARNING: JOERN_CONFIG not found: {path}", file=sys.stderr)
        return {}

    raw = path.read_text(encoding="utf-8")
    return json.loads(os.path.expandvars(raw))


def _resolve_runner_path(value: Any, fallback: str) -> str:
    """
    runner config 경로값을 정규화한다.

    환경변수 미치환 문자열("${VAR}")이 남아 있거나 비어 있으면 fallback을 사용한다.
    """
    if not isinstance(value, str):
        return fallback

    resolved = value.strip()
    if not resolved or "${" in resolved:
        return fallback
    return resolved


def _load_runner_rules(runner_cfg: dict[str, Any]) -> dict[str, Any]:
    """현재 JOERN language에 대응하는 rules JSON을 로드한다."""
    language = runner_cfg.get("project", {}).get("language", "php")
    path = RULES_DIR / f"{language}.json"
    if not path.exists():
        print(f"[NLD-MCP] WARNING: rules file not found: {path}", file=sys.stderr)
        return {}

    raw = path.read_text(encoding="utf-8")
    return json.loads(os.path.expandvars(raw))


# ──────────────────────────────────────────────────────────────────────────────
# 모듈 로드 시 1회 계산
# ──────────────────────────────────────────────────────────────────────────────

_runner_cfg   = _load_runner_config()
_runner_rules = _load_runner_rules(_runner_cfg)

RETRIEVER_OUTPUT_PATH, DIFF_RETRIEVER_PATH = _resolve_data_paths(_runner_cfg)

# ──────────────────────────────────────────────────────────────────────────────
# Joern 프로젝트 상수 (runner config + rules 에서 추출)
# ──────────────────────────────────────────────────────────────────────────────

JOERN_PROJECT_NAME = _runner_cfg.get("joern",  {}).get("workspace_project", "")
JOERN_LANGUAGE     = _runner_cfg.get("project", {}).get("language",         "php")
JOERN_TARGET_PATH  = _resolve_runner_path(
    _runner_cfg.get("paths", {}).get("container_source_root"),
    "/app/source",
)
JOERN_IMPORT     = _runner_rules.get("joern_import", JOERN_LANGUAGE)
JOERN_SOURCES    = _runner_rules.get("sources",    [])
JOERN_SINKS      = _runner_rules.get("sinks",      {})
JOERN_SANITIZERS = _runner_rules.get("sanitizers", [])
