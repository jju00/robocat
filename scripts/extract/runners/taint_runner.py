import argparse
import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import requests


class TaintRunner:
    def __init__(self, config: Dict[str, Any], rules: Dict[str, Any]):
        self.config = config
        self.rules = rules

        self.base_url = self._normalize_server_url(config["joern"]["server_url"])
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

    @staticmethod
    def _normalize_server_url(url: str) -> str:
        return url.rstrip("/")

    @staticmethod
    def load_json(path: Path) -> Dict[str, Any]:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def strip_ansi(text: str) -> str:
        return re.sub(r"\x1B\[[0-?]*[ -/]*[@-~]", "", text)

    @staticmethod
    def extract_res_string(stdout: str) -> str | None:
        # triple-quoted String
        m = re.findall(r'val res\d+: String = """(.*?)"""', stdout, re.DOTALL)
        if m:
            return m[-1]

        # normal quoted String
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
        """
        Escape Python/JSON string so it can be safely embedded inside
        a Scala/Joern string literal.
        """
        return value.replace("\\", "\\\\").replace('"', '\\"')

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

    def submit_query(self, query: str, timeout: int = 60) -> str:
        res = requests.post(
            f"{self.base_url}/query",
            json={"query": query},
            timeout=timeout,
        )
        res.raise_for_status()
        data = res.json()

        if "uuid" not in data:
            raise RuntimeError(f"UUID not found in response: {data}")

        return data["uuid"]

    def wait_for_result(
        self,
        uuid: str,
        poll_interval: int = 2,
        max_wait: int = 7200,
    ) -> Dict[str, Any]:
        start = time.time()

        while True:
            if time.time() - start > max_wait:
                raise TimeoutError(f"Query timed out: {uuid}")

            res = requests.get(f"{self.base_url}/result/{uuid}", timeout=30)
            res.raise_for_status()
            data = res.json()

            if data.get("success") is True:
                return data

            time.sleep(poll_interval)

    def build_import_query(self) -> str:
        import_stmt = f'importCode.{self.joern_import}("{self.target_path}", "{self.project_name}")'

        return rf'''
{import_stmt}
open("{self.project_name}")
run.ossdataflow

val summary =
  Map(
    "project_name" -> "{self.project_name}",
    "language" -> "{self.language}",
    "target_path" -> "{self.target_path}",
    "files" -> cpg.file.name.l.size,
    "methods" -> cpg.method.name.l.size,
    "calls" -> cpg.call.name.l.size,
    "identifiers" -> cpg.identifier.name.l.size
  )

ujson.write(ujson.read(summary.toJson), indent = 2)
'''

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
        source_expr = self.build_source_query_expr()
        escaped_sink_regex = self.escape_for_joern_string(sink_regex)

        return rf'''
import io.joern.dataflowengineoss.language.*

open("{self.project_name}")
run.ossdataflow

val sources =
  {source_expr}
    .l

val sinks =
  cpg.call
    .name("{escaped_sink_regex}")
    .argument
    .l

val flows =
  sinks.reachableByFlows(sources)
    .map(flow =>
      flow.elements.map(node =>
        Map(
          "line" -> node.lineNumber,
          "code" -> node.code,
          "type" -> node.label,
          "file" -> node.file.name.headOption.getOrElse("")
        )
      )
    ).l

val out =
  Map(
    "project_name" -> "{self.project_name}",
    "language" -> "{self.language}",
    "target_path" -> "{self.target_path}",
    "sink_name" -> "{sink_name}",
    "source_count" -> sources.size,
    "sink_count" -> sinks.size,
    "flow_count" -> flows.size,
    "flows" -> flows
  )

ujson.write(ujson.read(out.toJson), indent = 2)
'''

    def run_json_query(self, query: str) -> Dict[str, Any]:
        uuid = self.submit_query(query)
        result = self.wait_for_result(uuid)

        stdout = self.strip_ansi(result.get("stdout", ""))
        stderr = self.strip_ansi(result.get("stderr", ""))

        json_str = self.extract_res_string(stdout)
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
            parsed = {
                "raw_stdout": stdout
            }

        return {
            "success": result.get("success", False),
            "uuid": uuid,
            "parsed": parsed,
            "stdout": stdout,
            "stderr": stderr,
        }

    def import_project(self) -> Dict[str, Any]:
        print(f"[*] project import start: {self.target_path}")
        result = self.run_json_query(self.build_import_query())
        print(f"[+] import complete: {self.project_name}")
        return result

    def run_sink_analysis(self, sink_name: str, sink_regex: str) -> Dict[str, Any]:
        print(f"[*] sink analysis start: {sink_name}")
        result = self.run_json_query(self.build_taint_query(sink_name, sink_regex))
        parsed = result.get("parsed", {})
        flow_count = parsed.get("flow_count") if isinstance(parsed, dict) else None
        print(f"[+] sink analysis complete: {sink_name} | flow_count={flow_count}")
        return result

    def save_json(self, path: Path, data: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def analyze_all(self) -> Dict[str, Any]:
        final_result: Dict[str, Any] = {
            "project": {},
            "categories": {}
        }

        import_result = self.import_project()
        final_result["project"] = import_result

        for sink_name, sink_regex in self.sink_sets.items():
            sink_result = self.run_sink_analysis(sink_name, sink_regex)
            final_result["categories"][sink_name] = sink_result

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
    all_results = runner.analyze_all()

    summary = build_summary(all_results)
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()