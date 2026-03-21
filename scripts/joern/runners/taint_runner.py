import argparse
import asyncio
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from src.utils.joern_server import JoernClient  # noqa: E402

load_dotenv(Path(__file__).resolve().parents[3] / ".env")

_QUERIES_DIR = Path(__file__).resolve().parents[1] / "queries"


class TaintRunner:
    def __init__(self, config: Dict[str, Any], rules: Dict[str, Any]):
        self.config = config
        self.rules = rules

        self.project_name = config["joern"]["workspace_project"]
        self.target_path = config["paths"]["container_source_root"]
        self.taint_dir = Path(config["paths"]["taint_dir"])

        self.language = config["project"]["language"]
        self.joern_import = rules.get("joern_import", self.language)

        all_sinks = rules.get("sinks", {})
        enabled = config.get("analysis", {}).get("enabled_sink_categories", [])

        if enabled:
            self.sink_sets = {
                name: value["regex"]
                for name, value in all_sinks.items()
                if name in enabled
            }
        else:
            self.sink_sets = {
                name: value["regex"]
                for name, value in all_sinks.items()
            }

        self.source_rules = rules.get("sources", [])

        if not self.source_rules:
            raise ValueError("No source rules found in rules JSON.")
        if not self.sink_sets:
            raise ValueError("No enabled sink categories found.")

        raw_url = config["joern"]["server_url"].rstrip("/")
        host_port = raw_url.removeprefix("http://").removeprefix("https://")
        self._client = JoernClient(url=host_port, timeout=7200)

    @staticmethod
    def load_json(path: Path) -> Dict[str, Any]:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        return json.loads(os.path.expandvars(raw))

    @staticmethod
    def extract_output_marker(stdout: str) -> str | None:
        """Extract JSON from lines prefixed with 'OUTPUT: ' (println-based templates)."""
        for line in stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("OUTPUT: "):
                return stripped[len("OUTPUT: "):]
        return None

    @staticmethod
    def extract_res_string(stdout: str) -> str | None:
        """Fallback: extract from Joern REPL val assignment (val resN: String = ...)."""
        m = re.findall(r'val res\d+: String = """(.*?)"""', stdout, re.DOTALL)
        if m:
            return m[-1]

        m = re.findall(r'val res\d+: String = "(.*)"', stdout, re.DOTALL)
        if m:
            raw = m[-1]
            try:
                return raw.encode("utf-8").decode("unicode_escape")
            except Exception:
                return raw

        return None

    @staticmethod
    def escape_for_joern_string(value: str) -> str:
        """Escape a Python string for safe embedding inside a Scala/Joern string literal."""
        return value.replace("\\", "\\\\").replace('"', '\\"')

    @staticmethod
    def load_scala_template(name: str) -> str:
        """Load a .scala query template from the queries directory."""
        path = _QUERIES_DIR / name
        if not path.exists():
            raise FileNotFoundError(f"Scala template not found: {path}")
        return path.read_text(encoding="utf-8")

    @staticmethod
    def fill_template(template: str, **kwargs: str) -> str:
        """Replace $KEY placeholders in a scala template with provided values."""
        result = template
        for key, value in kwargs.items():
            result = result.replace(f"${key}", value)
        return result

    @staticmethod
    def normalize_parsed_json(parsed: Any) -> Any:
        """
        Joern/ujson output sometimes comes back as a list of single-key objects:
        [
          {"methods": 26989},
          {"calls": 1074204},
          ...
        ]
        Convert that into a flat dict for backward compatibility.
        """
        if isinstance(parsed, list):
            merged: Dict[str, Any] = {}
            for item in parsed:
                if isinstance(item, dict):
                    merged.update(item)
            return merged
        return parsed

    def build_import_query(self) -> str:
        template = self.load_scala_template("import_project.scala")
        return self.fill_template(
            template,
            JOERN_IMPORT=self.joern_import,
            TARGET_PATH=self.escape_for_joern_string(self.target_path),
            PROJECT_NAME=self.escape_for_joern_string(self.project_name),
            LANGUAGE=self.escape_for_joern_string(self.language),
        )

    def build_source_query_expr(self) -> str:
        """
        Support multiple source rule types:
        - identifier_regex
        - call_regex

        Result is converted into a common StoredNode iterator so reachableByFlows can use it.
        """
        exprs: List[str] = []

        for rule in self.source_rules:
            rule_type = rule.get("type")
            value = rule.get("value")

            if not value:
                continue

            escaped_value = self.escape_for_joern_string(value)

            if rule_type == "identifier_regex":
                exprs.append(
                    f'cpg.identifier.code("{escaped_value}").cast[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]'
                )
            elif rule_type == "call_regex":
                exprs.append(
                    f'cpg.call.name("{escaped_value}").cast[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]'
                )
            else:
                raise ValueError(f"Unsupported source rule type: {rule_type}")

        if not exprs:
            raise ValueError("No valid source expressions were generated.")

        if len(exprs) == 1:
            return exprs[0]

        return " ++ ".join(f"({expr})" for expr in exprs)

    def build_taint_query(self, sink_name: str, sink_regex: str) -> str:
        template = self.load_scala_template("tain_flow.scala")
        return self.fill_template(
            template,
            PROJECT_NAME=self.escape_for_joern_string(self.project_name),
            SOURCE_EXPR=self.build_source_query_expr(),
            SINK_REGEX=self.escape_for_joern_string(sink_regex),
            SINK_NAME=self.escape_for_joern_string(sink_name),
            LANGUAGE=self.escape_for_joern_string(self.language),
            TARGET_PATH=self.escape_for_joern_string(self.target_path),
        )

    async def run_json_query(self, query: str) -> Dict[str, Any]:
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
        parsed: Any = None

        if json_str:
            try:
                parsed = json.loads(json_str)
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

    async def import_project(self) -> Dict[str, Any]:
        print(f"[*] project import start: {self.target_path}")
        result = await self.run_json_query(self.build_import_query())
        print(f"[+] import complete: {self.project_name}")
        return result

    async def run_sink_analysis(self, sink_name: str, sink_regex: str) -> Dict[str, Any]:
        print(f"[*] sink analysis start: {sink_name}")
        result = await self.run_json_query(self.build_taint_query(sink_name, sink_regex))
        parsed = result.get("parsed", {})
        flow_count = parsed.get("flow_count") if isinstance(parsed, dict) else None
        print(f"[+] sink analysis complete: {sink_name} | flow_count={flow_count}")
        return result

    def save_json(self, path: Path, data: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    async def analyze_all(self) -> Dict[str, Any]:
        import_result = await self.import_project()

        tasks = {
            name: asyncio.create_task(self.run_sink_analysis(name, regex))
            for name, regex in self.sink_sets.items()
        }
        sink_results: Dict[str, Any] = dict(
            zip(tasks.keys(), await asyncio.gather(*tasks.values()))
        )

        final_result: Dict[str, Any] = {
            "project": import_result,
            "categories": sink_results,
        }

        for sink_name, sink_result in sink_results.items():
            sink_path = self.taint_dir / f"taint_{sink_name}.json"
            self.save_json(sink_path, sink_result)

        all_path = self.taint_dir / "taint_results_all.json"
        self.save_json(all_path, final_result)

        return final_result


def build_summary(all_results: Dict[str, Any]) -> Dict[str, Any]:
    project_summary = all_results.get("project", {}).get("parsed", {})
    category_summary = {}

    for name, result in all_results.get("categories", {}).items():
        parsed = result.get("parsed", {})
        if isinstance(parsed, dict):
            category_summary[name] = {
                "source_count": parsed.get("source_count"),
                "sink_count": parsed.get("sink_count"),
                "flow_count": parsed.get("flow_count"),
            }
        else:
            category_summary[name] = {
                "source_count": None,
                "sink_count": None,
                "flow_count": None,
            }

    return {
        "project_summary": project_summary,
        "category_summary": category_summary
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Config-driven multi-language Joern taint runner")
    parser.add_argument(
        "--config",
        default=None,
        help="Path to project config JSON (default: runners/configs/phpmyadmin.json)",
    )
    parser.add_argument(
        "--rules",
        default=None,
        help="Path to language rules JSON (default: inferred from config project.language)",
    )
    return parser.parse_args()


def resolve_default_paths(args: argparse.Namespace) -> Tuple[Path, Path]:
    base_dir = Path(__file__).resolve().parent
    config_path = Path(args.config) if args.config else (base_dir / "configs" / "phpmyadmin.json")

    config = TaintRunner.load_json(config_path)
    language = config["project"]["language"]

    rules_path = Path(args.rules) if args.rules else (base_dir / "rules" / f"{language}.json")
    return config_path, rules_path


def main() -> None:
    args = parse_args()
    config_path, rules_path = resolve_default_paths(args)

    config = TaintRunner.load_json(config_path)
    rules = TaintRunner.load_json(rules_path)

    runner = TaintRunner(config=config, rules=rules)
    all_results = asyncio.run(runner.analyze_all())

    summary = build_summary(all_results)
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()