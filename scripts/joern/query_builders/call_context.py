from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

_DEFAULT_QUERIES_DIR = Path(__file__).resolve().parents[1] / "queries"


class CallContextQueryBuilder:
    """
    method_call_context.scala 템플릿을 기반으로 함수별 callee/caller 쿼리를 생성.

    diff_functions.json 의 파일/함수 목록에서 온디맨드로 쿼리를 빌드한다.
    외부 의존성 없이 순수하게 문자열만 조립한다.
    """

    def __init__(
        self,
        project_name: str,
        language: str,
        target_path: str,
        queries_dir: Path | None = None,
    ):
        self._queries_dir = queries_dir or _DEFAULT_QUERIES_DIR
        self.project_name = project_name
        self.language = language
        self.target_path = target_path

    # ── Template ──────────────────────────────────────────────────────────────

    def _load_template(self, name: str) -> str:
        path = self._queries_dir / name
        if not path.exists():
            raise FileNotFoundError(f"Scala template not found: {path}")
        return path.read_text(encoding="utf-8")

    @staticmethod
    def _fill(template: str, **kwargs: str) -> str:
        result = template
        for key, value in kwargs.items():
            result = result.replace(f"${key}", value)
        return result

    # ── Escape ────────────────────────────────────────────────────────────────

    @staticmethod
    def escape(value: str) -> str:
        """Python 문자열을 Scala/Joern 문자열 리터럴 안에 안전하게 삽입할 수 있도록 이스케이프."""
        return value.replace("\\", "\\\\").replace('"', '\\"')

    # ── Function name parsing ─────────────────────────────────────────────────

    @staticmethod
    def parse_method_name(raw: str) -> str:
        """
        diff_functions.json 의 function 필드에서 메서드 이름만 추출.

        "ClassName::methodName" -> "methodName"
        "plainFunction"         -> "plainFunction"
        """
        return raw.split("::")[-1]

    # ── Single query builder ──────────────────────────────────────────────────

    def build_call_context_query(
        self,
        file_path: str,
        function_name: str,
        depth: int = 1,
        duplicate_mode: str = "auto",
        target_line: int = -1,
    ) -> str:
        """
        특정 파일/함수에 대한 call context (callee + caller) 쿼리를 생성.

        Args:
            file_path:     CPG 내 파일 경로  (예: "libraries/classes/Advisor.php")
            function_name: 함수명. "ClassName::method" 형식이면 메서드명만 자동 파싱.
            depth:         call graph 확장 깊이 (기본 1)
            duplicate_mode: duplicate 함수 선택 모드.
                            auto | exact_file | exact_file_line
            target_line:   exact_file_line 모드에서 사용할 함수 정의 line
        """
        method_name = self.parse_method_name(function_name)
        norm_depth = max(1, int(depth))
        mode = (duplicate_mode or "auto").strip().lower()
        if mode not in {"auto", "exact_file", "exact_file_line"}:
            mode = "auto"
        return self._fill(
            self._load_template("method_call_context.scala"),
            PROJECT_NAME=self.escape(self.project_name),
            FILE_PATH=self.escape(file_path),
            FUNCTION_NAME=self.escape(method_name),
            DEPTH=str(norm_depth),
            DUPLICATE_MODE=self.escape(mode),
            TARGET_LINE=str(int(target_line)),
            LANGUAGE=self.escape(self.language),
            TARGET_PATH=self.escape(self.target_path),
        )

    # ── Batch helpers ─────────────────────────────────────────────────────────

    def iter_queries_from_diff(
        self, diff_data: Dict[str, Any]
    ) -> Iterator[Tuple[str, str, str]]:
        """
        diff_functions.json 데이터 전체를 순회하며 (file_path, raw_function, query) 를 지연 생성.

        Args:
            diff_data: diff_functions.json 을 파싱한 dict

        Yields:
            (file_path, raw_function_name, query_string)
        """
        for file_entry in diff_data.get("files", []):
            file_path = file_entry.get("file_path", "")
            for fn_entry in file_entry.get("functions", []):
                raw_name = fn_entry.get("function", "")
                if not raw_name:
                    continue
                yield file_path, raw_name, self.build_call_context_query(file_path, raw_name)

    def build_all_queries_from_diff(
        self, diff_data: Dict[str, Any]
    ) -> List[Tuple[str, str, str]]:
        """
        iter_queries_from_diff 의 목록 버전.

        Returns:
            [(file_path, raw_function_name, query_string), ...]
        """
        return list(self.iter_queries_from_diff(diff_data))
