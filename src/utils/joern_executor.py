import asyncio
import json
import re
from pathlib import Path
from typing import Any

from src.utils.joern_server import JoernClient

_DEFAULT_QUERIES_DIR = Path(__file__).resolve().parents[2] / "scripts" / "joern" / "queries"


class JoernExecutor:
    """
    Joern 쿼리 실행 및 결과 파싱 오케스트레이터.

    JoernClient 위에서 동작하며:
      - Scala 템플릿 로드 / 치환
      - /query-sync 비동기 실행 (asyncio.to_thread)
      - stdout 파싱 (OUTPUT 마커 → REPL val 바인딩 순으로 시도)
      - ujson list-of-dicts → flat dict 정규화
    """

    def __init__(self, client: JoernClient, queries_dir: Path | None = None):
        self._client = client
        self._queries_dir = queries_dir or _DEFAULT_QUERIES_DIR

    # ── Template ──────────────────────────────────────────────────────────────

    def load_scala_template(self, name: str) -> str:
        """queries 디렉토리에서 .scala 템플릿 파일을 읽어 반환."""
        path = self._queries_dir / name
        if not path.exists():
            raise FileNotFoundError(f"Scala template not found: {path}")
        return path.read_text(encoding="utf-8")

    @staticmethod
    def fill_template(template: str, **kwargs: str) -> str:
        """$KEY 플레이스홀더를 kwargs 값으로 치환."""
        result = template
        for key, value in kwargs.items():
            result = result.replace(f"${key}", value)
        return result

    # ── Parsing ───────────────────────────────────────────────────────────────

    @staticmethod
    def extract_output_marker(stdout: str) -> str | None:
        """
        Joern REPL stdout 에서 JSON 문자열을 추출.

        우선순위:
          1) val __OUTPUT__: String = "..."  — 템플릿 마지막 바인딩 방식
          2) val __OUTPUT__: String = \"\"\"...\"\"\"  — 멀티라인(indent) 방식
          3) val resN: String = \"\"\"...\"\"\"  — taint_flow 등 마지막 resN 트리플-쿼트
          4) (레거시) OUTPUT:  접두어 줄
        """
        # 1) & 2) __OUTPUT__ 명시 바인딩 — 트리플쿼트
        m = re.search(r'val __OUTPUT__: String = """(.*?)"""', stdout, re.DOTALL)
        if m:
            return m.group(1).strip()

        # 1) __OUTPUT__ 싱글쿼트 — escape 디코딩 필요
        m = re.search(r'val __OUTPUT__: String = "((?:[^"\\]|\\.)*)"', stdout)
        if m:
            return JoernExecutor._decode_scala_string(m.group(1))

        # 3) resN 트리플쿼트 (마지막 매치)
        matches = re.findall(r'val res\d+: String = """(.*?)"""', stdout, re.DOTALL)
        if matches:
            return matches[-1].strip()

        # 4) 레거시 println 방식
        for line in stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("OUTPUT: "):
                return stripped[len("OUTPUT: "):]

        return None

    @staticmethod
    def extract_res_string(stdout: str) -> str | None:
        """이전 버전 호환: extract_output_marker 로 위임."""
        return JoernExecutor.extract_output_marker(stdout)

    @staticmethod
    def _decode_scala_string(s: str) -> str:
        """Scala/Java 문자열 이스케이프(\\", \\n, \\\\…)를 Python str 로 디코딩."""
        import json as _json
        try:
            return _json.loads(f'"{s}"')
        except Exception:
            return s

    @staticmethod
    def normalize_parsed_json(parsed: Any) -> Any:
        """
        ujson이 Map을 직렬화할 때 단일 키 오브젝트 배열로 출력하는 경우 flat dict으로 변환.

        예) [{"methods": 1}, {"calls": 0}] → {"methods": 1, "calls": 0}
        """
        if isinstance(parsed, list):
            merged: dict[str, Any] = {}
            for item in parsed:
                if isinstance(item, dict):
                    merged.update(item)
            return merged
        return parsed

    # ── Execution ─────────────────────────────────────────────────────────────

    async def run_query(self, query: str) -> dict[str, Any]:
        """
        Scala 쿼리를 JoernClient를 통해 비동기로 실행하고 파싱된 결과를 반환.

        반환 구조:
            {
                "success": bool,
                "parsed":  dict  (JSON 파싱 성공 시) | {"raw_stdout": str} (실패 시),
                "stdout":  str,
                "stderr":  str,
            }
        """
        res, valid = await asyncio.to_thread(self._client.query, query)

        if not valid:
            return {
                "success": False,
                "parsed": {"raw_stdout": ""},
                "stdout": "",
                "stderr": "request failed (timeout or connection error)",
            }

        stdout = res.get("stdout", "")
        stderr = res.get("stderr", "")

        json_str = self.extract_output_marker(stdout) or self.extract_res_string(stdout)

        if json_str:
            try:
                parsed: Any = json.loads(json_str)
                parsed = self.normalize_parsed_json(parsed)
            except json.JSONDecodeError:
                parsed = {
                    "raw_json_string": json_str,
                    "raw_stdout": stdout,
                }
        else:
            parsed = {"raw_stdout": stdout}

        return {
            "success": res.get("success", False),
            "parsed": parsed,
            "stdout": stdout,
            "stderr": stderr,
        }

    async def run_template(self, template_name: str, **kwargs: str) -> dict[str, Any]:
        """템플릿 로드 → 치환 → 실행 → 파싱을 한 번에 처리."""
        template = self.load_scala_template(template_name)
        query = self.fill_template(template, **kwargs)
        return await self.run_query(query)
