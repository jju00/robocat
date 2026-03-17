'''
joern-server에 쿼리를 보내서 source, sink, source-sink flow를 추출하고 카테고리별 json 저장
port: joern-server가 리스닝하는 포트 (기본값: 9001)
target_path: 분석할 소스코드 경로(/app/phpmyadmin) <- docker volume로 마운트된 phpmyadmin 소스코드 경로
project_name: 프로젝트 이름(pma_root) <- joern에서 사용할 프로젝트 이름
'''

import requests
import json
import time
import re
from typing import Any, Dict


class NLDSingleAnalyzer:
    def __init__(self, port: int = 9001):
        self.base_url = f"http://localhost:{port}"

        self.sink_sets = {
            "sqli": r"(mysqli_query|mysql_query)",
            "include": r"(include|include_once|require|require_once)",
            "command": r"(exec|system|passthru|shell_exec)",
            "eval": r"(eval)",
            "xss": r"(echo|print)",
        }

    def submit_query(self, query: str, timeout: int = 60) -> str:
        res = requests.post(
            f"{self.base_url}/query",
            json={"query": query},
            timeout=timeout,
        )
        res.raise_for_status()
        data = res.json()

        if "uuid" not in data:
            raise RuntimeError(f"UUID 응답이 아님: {data}")

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
                raise TimeoutError(f"쿼리 시간 초과: {uuid}")

            res = requests.get(f"{self.base_url}/result/{uuid}", timeout=30)
            res.raise_for_status()
            data = res.json()

            if data.get("success") is True:
                return data

            time.sleep(poll_interval)

    @staticmethod
    def strip_ansi(text: str) -> str:
        return re.sub(r"\x1B\[[0-?]*[ -/]*[@-~]", "", text)

    @staticmethod
    def extract_res_string(stdout: str) -> str | None:
        # 1) triple-quoted String
        matches = re.findall(r'val res\d+: String = """(.*?)"""', stdout, re.DOTALL)
        if matches:
            return matches[-1]

        # 2) normal quoted String
        matches = re.findall(r'val res\d+: String = "(.*)"', stdout, re.DOTALL)
        if matches:
            raw = matches[-1]
            try:
                return raw.encode("utf-8").decode("unicode_escape")
            except Exception:
                return raw

        return None

    @staticmethod
    def normalize_parsed_json(data: Any) -> Any:
        # [{"a":1},{"b":2}] -> {"a":1,"b":2}
        if isinstance(data, list):
            merged = {}
            all_singleton_dict = True
            for item in data:
                if isinstance(item, dict) and len(item) == 1:
                    merged.update(item)
                else:
                    all_singleton_dict = False
                    break
            if all_singleton_dict:
                return merged
        return data

    def build_import_query(self, target_path: str, project_name: str) -> str:
        return rf'''
importCode.php("{target_path}", "{project_name}")
open("{project_name}")
run.ossdataflow

ujson.Obj(
  "project_name" -> "{project_name}",
  "target_path" -> "{target_path}",
  "files" -> cpg.file.name.l.size,
  "methods" -> cpg.method.name.l.size,
  "calls" -> cpg.call.name.l.size,
  "identifiers" -> cpg.identifier.name.l.size
).render(indent = 2)
'''

    def build_taint_query(self, project_name: str, sink_name: str, sink_regex: str) -> str:
        return rf'''
import io.joern.dataflowengineoss.language.*

open("{project_name}")
run.ossdataflow

val sources =
  cpg.identifier
    .code(".*\\$_(GET|POST|REQUEST|COOKIE|SERVER).*")
    .l

val sinks =
  cpg.call
    .name("{sink_regex}")
    .argument
    .l

val flows =
  sinks.reachableByFlows(sources)
    .map(flow =>
      flow.elements.map(node =>
        ujson.Obj(
          "line" -> node.lineNumber.getOrElse(-1),
          "code" -> node.code,
          "type" -> node.label,
          "file" -> node.file.name.headOption.getOrElse("")
        )
      )
    ).l

ujson.Obj(
  "sink_name" -> "{sink_name}",
  "project_name" -> "{project_name}",
  "source_count" -> sources.size,
  "sink_count" -> sinks.size,
  "flow_count" -> flows.size,
  "flows" -> flows
).render(indent = 2)
'''

    def run_json_query(self, query: str) -> Dict[str, Any]:
        uuid = self.submit_query(query)
        result = self.wait_for_result(uuid)

        stdout = self.strip_ansi(result.get("stdout", ""))
        stderr = self.strip_ansi(result.get("stderr", ""))

        json_str = self.extract_res_string(stdout)
        parsed: Any

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

    def import_project(self, target_path: str, project_name: str) -> Dict[str, Any]:
        print(f"[*] 프로젝트 import 시작: {target_path}")
        query = self.build_import_query(target_path, project_name)
        result = self.run_json_query(query)
        print(f"[+] import 완료: {project_name}")
        return result

    def run_sink_analysis(self, project_name: str, sink_name: str, sink_regex: str) -> Dict[str, Any]:
        print(f"[*] sink 분석 시작: {sink_name}")
        query = self.build_taint_query(project_name, sink_name, sink_regex)
        result = self.run_json_query(query)

        parsed = result.get("parsed", {})
        flow_count = parsed.get("flow_count") if isinstance(parsed, dict) else None
        print(f"[+] sink 분석 완료: {sink_name} | flow_count={flow_count}")

        return result

    def analyze_all(self, target_path: str, project_name: str = "pma_root") -> Dict[str, Any]:
        final_result: Dict[str, Any] = {
            "project": {},
            "categories": {}
        }

        import_result = self.import_project(target_path, project_name)
        final_result["project"] = import_result

        for sink_name, sink_regex in self.sink_sets.items():
            sink_result = self.run_sink_analysis(project_name, sink_name, sink_regex)
            final_result["categories"][sink_name] = sink_result

            with open(f"taint_{sink_name}.json", "w", encoding="utf-8") as f:
                json.dump(sink_result, f, indent=2, ensure_ascii=False)

        return final_result


if __name__ == "__main__":
    analyzer = NLDSingleAnalyzer(port=9001)

    target_path = "/app/phpmyadmin"
    project_name = "pma_root"

    all_results = analyzer.analyze_all(target_path, project_name)

    with open("taint_results_all.json", "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)

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

    print(json.dumps({
        "project_summary": project_summary,
        "category_summary": category_summary
    }, indent=2, ensure_ascii=False))