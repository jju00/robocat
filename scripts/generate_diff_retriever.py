import json
from pathlib import Path
import yaml
import os
from openai import OpenAI


# =========================
# Paths
# =========================
BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_PATH = BASE_DIR / "data" / "diff" / "llm_scope_functions.json"
OUTPUT_PATH = BASE_DIR / "data" / "diff" / "diff_retriever.json"
PROMPT_PATH = BASE_DIR / "src" / "prompts" / "extract_knowledge.yaml"


# =========================
# Load prompts
# =========================
with open(PROMPT_PATH, "r", encoding="utf-8") as f:
    prompt_yaml = yaml.safe_load(f)

prefix_template = prompt_yaml["prefix"]
purpose_template = prompt_yaml["purpose"]
function_template = prompt_yaml["function_summary"]


# =========================
# OpenAI client
# =========================
client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)

MODEL = "gpt-4o-mini"


# =========================
# LLM 호출 함수
# =========================
def ask_llm(prompt):

    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "user", "content": prompt}
        ],
        temperature=0
    )

    return response.choices[0].message.content.strip()


# =========================
# 입력 JSON 로드
# =========================
with open(INPUT_PATH, "r", encoding="utf-8") as f:
    data = json.load(f)

project = data["project"]
from_version = data["from_version"]
test_version = data["test_version"]

results = []


# =========================
# 메인 루프
# =========================
for file in data["files"]:

    file_path = file["file_path"]

    for func in file["functions"]:

        function_name = func["function"]
        full_code = func["full_code"]

        # global placeholder 제거
        if not full_code.strip():
            continue

        # prefix 생성
        prefix = prefix_template.format_map({
            "cve_id": "unknown",
            "code_before": full_code,
            "cve_description": "N/A"
        })

        # purpose prompt
        purpose_prompt = purpose_template.format_map({
            "prefix": prefix
        })

        # function summary prompt
        function_prompt = function_template.format_map({
            "prefix": prefix
        })

        # LLM 호출
        purpose = ask_llm(purpose_prompt)
        function_summary = ask_llm(function_prompt)

        # DTO 구조 생성
        dto = {
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


# =========================
# JSON 저장
# =========================
OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=4, ensure_ascii=False)

print(f"Saved: {OUTPUT_PATH}")
print(f"Total functions processed: {len(results)}")