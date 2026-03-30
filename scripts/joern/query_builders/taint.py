from pathlib import Path
from typing import Any, Dict, List

_DEFAULT_QUERIES_DIR = Path(__file__).resolve().parents[1] / "queries"
_STORED_NODE = "io.shiftleft.codepropertygraph.generated.nodes.StoredNode"


class TaintQueryBuilder:
    """
    Joern DSL 쿼리 문자열 생성 계층.

    어떤 템플릿을 쓸지 결정하고, config/rules 컨텍스트를 Joern DSL 표현으로 변환한다.
    네트워크 통신 및 외부 의존성 없이 순수하게 문자열을 조립한다.
    """

    def __init__(
        self,
        project_name: str,
        target_path: str,
        language: str,
        joern_import: str,
        source_rules: List[Dict[str, Any]],
        queries_dir: Path | None = None,
    ):
        self._queries_dir = queries_dir or _DEFAULT_QUERIES_DIR
        self.project_name = project_name
        self.target_path = target_path
        self.language = language
        self.joern_import = joern_import
        self.source_rules = source_rules

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

    # ── DSL expression builders ───────────────────────────────────────────────

    def build_source_query_expr(self) -> str:
        """
        source rules를 Joern DSL 표현식(StoredNode 이터레이터)으로 변환.

        지원 타입:
          - identifier_regex : cpg.identifier.code(...)
          - call_regex        : cpg.call.name(...)

        복수 룰이면 ++ 연산자로 결합하여 reachableByFlows에 전달 가능한 단일 표현식을 반환.
        """
        exprs: List[str] = []

        for rule in self.source_rules:
            rule_type = rule.get("type")
            value = rule.get("value")

            if not value:
                continue

            esc = self.escape(value)

            if rule_type == "identifier_regex":
                exprs.append(f'cpg.identifier.code("{esc}").cast[{_STORED_NODE}]')
            elif rule_type == "call_regex":
                exprs.append(f'cpg.call.name("{esc}").cast[{_STORED_NODE}]')
            else:
                raise ValueError(f"Unsupported source rule type: {rule_type!r}")

        if not exprs:
            raise ValueError("No valid source expressions were generated from source_rules.")

        if len(exprs) == 1:
            return exprs[0]

        return " ++ ".join(f"({e})" for e in exprs)

    # ── Full query builders ───────────────────────────────────────────────────

    def build_import_query(self, run_dataflow: bool = False) -> str:
        """import_cpg.scala 템플릿을 로드하여 프로젝트 임포트 쿼리를 생성."""
        return self._fill(
            self._load_template("import_cpg.scala"),
            JOERN_IMPORT=self.joern_import,
            TARGET_PATH=self.escape(self.target_path),
            PROJECT_NAME=self.escape(self.project_name),
            LANGUAGE=self.escape(self.language),
            RUN_DATAFLOW="true" if run_dataflow else "false",
        )

    def build_taint_query(self, sink_name: str, sink_regex: str) -> str:
        """taint_flow.scala 템플릿을 로드하여 소스→싱크 taint flow 쿼리를 생성."""
        return self._fill(
            self._load_template("taint_flow.scala"),
            PROJECT_NAME=self.escape(self.project_name),
            SOURCE_EXPR=self.build_source_query_expr(),
            SINK_REGEX=self.escape(sink_regex),
            SINK_NAME=self.escape(sink_name),
            LANGUAGE=self.escape(self.language),
            TARGET_PATH=self.escape(self.target_path),
        )

    def build_protection_query(
        self,
        sink_name: str,
        sink_regex: str,
        sanitizers: List[str],
        file_path: str = ".*",
        function_name: str = ".*",
    ) -> str:
        """check_protection.scala 템플릿을 로드하여 보호 기법 판단 쿼리를 생성"""
        sanitizer_regex = "|".join(sanitizers) if sanitizers else "NEVER_MATCH_ANYTHING"
        
        return self._fill(
            self._load_template("check_protection.scala"),
            PROJECT_NAME=self.escape(self.project_name),
            SOURCE_EXPR=self.build_source_query_expr(),
            SINK_REGEX=self.escape(sink_regex),
            SINK_NAME=self.escape(sink_name),
            SANITIZER_REGEX=self.escape(sanitizer_regex),
            FILE_PATH=self.escape(file_path),
            FUNCTION_NAME=self.escape(function_name),
            LANGUAGE=self.escape(self.language),
            TARGET_PATH=self.escape(self.target_path),
        )
