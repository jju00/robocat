import json
from pathlib import Path
import yaml
import os
import argparse
from openai import OpenAI


# =========================
# Paths
# =========================
BASE_DIR = Path(__file__).resolve().parent.parent
PROMPT_PATH = BASE_DIR / "src" / "prompts" / "extract_knowledge.yaml"


# =========================
# CLI
# =========================
def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate diff_retriever.json from llm_scope_functions-style input"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Input JSON path (e.g. data/diff/llm_scope_functions.json)"
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output JSON path (e.g. data/diff/diff_retriever.json)"
    )
    return parser.parse_args()


# =========================
# Load prompts
# =========================
def load_prompts(prompt_path: Path):
    with open(prompt_path, "r", encoding="utf-8") as f:
        prompt_yaml = yaml.safe_load(f)

    prefix_template = prompt_yaml["prefix"]
    purpose_template = prompt_yaml["purpose"]
    function_template = prompt_yaml["function_summary"]

    return prefix_template, purpose_template, function_template


# =========================
# OpenAI client
# =========================
def build_client():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY is not set")

    return OpenAI(api_key=api_key)


MODEL = "gpt-4o-mini"


# =========================
# LLM 호출 함수
# =========================
def ask_llm(client: OpenAI, prompt: str) -> str:
    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "user", "content": prompt}
        ],
        temperature=0
    )
    return response.choices[0].message.content.strip()


# =========================
# Main
# =========================
def main():
    args = parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.is_absolute():
        input_path = BASE_DIR / input_path

    if not output_path.is_absolute():
        output_path = BASE_DIR / output_path

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    if not PROMPT_PATH.exists():
        raise FileNotFoundError(f"Prompt file not found: {PROMPT_PATH}")

    prefix_template, purpose_template, function_template = load_prompts(PROMPT_PATH)
    client = build_client()

    # =========================
    # 입력 JSON 로드
    # =========================
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    project = data.get("project", "")
    from_version = data.get("from_version", "")
    test_version = data.get("test_version", "")

    results = []

    # =========================
    # 메인 루프
    # =========================
    for file in data.get("files", []):
        file_path = file.get("file_path", "")

        for func in file.get("functions", []):
            function_name = func.get("function", "")

            # full_code 우선, 없으면 code_after_change 사용
            full_code = func.get("full_code") or func.get("code_after_change", "")

            if not isinstance(full_code, str):
                full_code = str(full_code)

            if not full_code.strip():
                continue

            prefix = prefix_template.format_map({
                "cve_id": "unknown",
                "code_before": full_code,
                "cve_description": "N/A"
            })

            purpose_prompt = purpose_template.format_map({
                "prefix": prefix
            })

            function_prompt = function_template.format_map({
                "prefix": prefix
            })

            purpose = ask_llm(client, purpose_prompt)
            function_summary = ask_llm(client, function_prompt)

            dto = {
                "id": len(results) + 1,
                "project": project,
                "from_version": from_version,
                "test_version": test_version,
                "file_path": file_path,
                "function": function_name,
                "full_code": full_code,
                "purpose": purpose,
                "function_summary": function_summary
            }

            results.append(dto)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    print(f"Saved: {output_path}")
    print(f"Total functions processed: {len(results)}")


if __name__ == "__main__":
    main()