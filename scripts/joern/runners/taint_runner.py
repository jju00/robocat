import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Tuple

from dotenv import load_dotenv

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_JOERN_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_JOERN_DIR))

from src.utils.joern_server import JoernClient           # noqa: E402
from src.utils.joern_executor import JoernExecutor       # noqa: E402
from query_builders.taint import TaintQueryBuilder       # noqa: E402

load_dotenv(_PROJECT_ROOT / ".env")


class TaintRunner:
    def __init__(self, config: Dict[str, Any], rules: Dict[str, Any]):
        self.config = config
        self.rules = rules

        self.project_name = config["joern"]["workspace_project"]
        self.target_path = config["paths"]["container_source_root"]
        self.taint_dir = Path(config["paths"]["taint_dir"])

        self.language = config["project"]["language"]
        joern_import = rules.get("joern_import", self.language)

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
        self.sanitizers = rules.get("sanitizers", [])

        if not self.source_rules:
            raise ValueError("No source rules found in rules JSON.")
        if not self.sink_sets:
            raise ValueError("No enabled sink categories found.")

        raw_url = config["joern"]["server_url"].rstrip("/")
        host_port = raw_url.removeprefix("http://").removeprefix("https://")

        self._executor = JoernExecutor(JoernClient(url=host_port, timeout=7200))
        self._builder = TaintQueryBuilder(
            project_name=self.project_name,
            target_path=self.target_path,
            language=self.language,
            joern_import=joern_import,
            source_rules=self.source_rules,
        )

    @staticmethod
    def load_json(path: Path) -> Dict[str, Any]:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        return json.loads(os.path.expandvars(raw))

    async def import_project(self) -> Dict[str, Any]:
        print(f"[*] project import start: {self.target_path}")
        result = await self._executor.run_query(self._builder.build_import_query())
        print(f"[+] import complete: {self.project_name}")
        return result

    async def run_sink_analysis(self, sink_name: str, sink_regex: str) -> Dict[str, Any]:
        print(f"[*] sink analysis start: {sink_name}")
        result = await self._executor.run_query(self._builder.build_taint_query(sink_name, sink_regex))
        parsed = result.get("parsed", {})
        flow_count = parsed.get("flow_count") if isinstance(parsed, dict) else None
        print(f"[+] sink analysis complete: {sink_name} | flow_count={flow_count}")
        return result

    async def run_protection_analysis(self, sink_name: str, sink_regex: str) -> Dict[str, Any]:
        """보호 기법 적용 여부 분석 실행"""
        print(f"[*] protection analysis start: {sink_name}")
        query = self._builder.build_protection_query(sink_name, sink_regex, self.sanitizers)
        result = await self._executor.run_query(query)
        print(f"[+] protection analysis complete: {sink_name}")
        return result

    def save_json(self, path: Path, data: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    async def analyze_all(self) -> Dict[str, Any]:
        import_result = await self.import_project()

        sink_tasks = {}
        prot_tasks = {}
        
        for name, regex in self.sink_sets.items():
            sink_tasks[name] = asyncio.create_task(self.run_sink_analysis(name, regex))
            prot_tasks[name] = asyncio.create_task(self.run_protection_analysis(name, regex))

        sink_results = {name: await task for name, task in sink_tasks.items()}
        prot_results = {name: await task for name, task in prot_tasks.items()}

        final_result: Dict[str, Any] = {
            "project": import_result,
            "categories": sink_results,
            "protections": prot_results,
        }

        for sink_name in sink_results.keys():
            sink_path = self.taint_dir / f"taint_{sink_name}.json"
            self.save_json(sink_path, sink_results[sink_name])
            
            prot_path = self.taint_dir / f"protection_{sink_name}.json"
            self.save_json(prot_path, prot_results[sink_name])

        all_path = self.taint_dir / "taint_results_all.json"
        self.save_json(all_path, final_result)

        return final_result


def build_summary(all_results: Dict[str, Any]) -> Dict[str, Any]:
    project_summary = all_results.get("project", {}).get("parsed", {})
    category_summary = {}

    for name, result in all_results.get("categories", {}).items():
        parsed = result.get("parsed", {})
        prot_parsed = all_results.get("protections", {}).get(name, {}).get("parsed", {})
        
        if isinstance(parsed, dict):
            category_summary[name] = {
                "source_count": parsed.get("source_count"),
                "sink_count": parsed.get("sink_count"),
                "flow_count": parsed.get("flow_count"),
                "protected_count": prot_parsed.get("protected_flows") if isinstance(prot_parsed, dict) else 0
            }
        else:
            category_summary[name] = {
                "source_count": None,
                "sink_count": None,
                "flow_count": None,
                "protected_count": None
            }

    return {
        "project_summary": project_summary,
        "category_summary": category_summary,
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