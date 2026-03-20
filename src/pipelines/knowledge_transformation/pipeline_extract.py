"""
Knowledge Extraction Pipeline
RawDiffDTO JSON → LLM 분석 → VulnerabilityKnowledgeDTO JSON

Usage:
    # 단일 파일
    python src/pipelines/knowledge_transformation/pipeline_extract.py \
        --lang c \
        --input_file_name CWE-119.json \
        --output_file_name CWE-119_knowledge.json \
        --model_name gpt-4o-mini \
        --model_settings "temperature=0.2;max_tokens=4096" \
        --thread_pool_size 5 \
        --retry_time 3 \
        --resume

    # 언어별 전체 배치
    python src/pipelines/knowledge_transformation/pipeline_extract.py \
        --lang c \
        --batch \
        --model_name gpt-4o-mini \
        --model_settings "temperature=0.2;max_tokens=4096" \
        --thread_pool_size 5 \
        --retry_time 3 \
        --resume
"""
import json
import os
import sys
import argparse
from pathlib import Path

import yaml

from ...utils import llm_client
from ...dto.vulnerability_knowledge_dto import VulnerabilityKnowledgeDTO, VulnerabilityBehavior
from tqdm import tqdm
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any
import time
from functools import wraps

MODEL_CLIENT = None
output_lock = threading.Lock()
file_lock = threading.Lock()

_PROMPTS = None
_PROMPTS_PATH = Path(__file__).parent.parent.parent / "prompts" / "extract_knowledge.yaml"

LANG_CHOICES = ["php", "c", "cpp"]


def _load_prompts() -> dict:
    """YAML 프롬프트 파일을 로드 (최초 1회만 읽음)"""
    global _PROMPTS
    if _PROMPTS is None:
        with open(_PROMPTS_PATH, "r", encoding="utf-8") as f:
            _PROMPTS = yaml.safe_load(f)
    return _PROMPTS


def retry_on_failure(max_retries: int = 5, delay: float = 1.0):
    """재시도 데코레이터"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        print(f"Attempt {attempt + 1}/{max_retries} failed: {str(e)}")
                        time.sleep(delay)
                    continue
            raise last_exception
        return wrapper
    return decorator


def parse_args():
    """명령줄 인자 파싱"""
    parser = argparse.ArgumentParser(description="Extract vulnerability knowledge using LLM")
    parser.add_argument(
        "--lang",
        type=str,
        choices=LANG_CHOICES,
        required=False,
        help="Language folder under data/train and data/knowledge (php, c, cpp)"
    )
    parser.add_argument(
        "--input_file_name",
        type=str,
        required=False,
        help="Input JSON file name (in data/train/<lang>/ if --lang is set, else data/train/)"
    )
    parser.add_argument(
        "--output_file_name",
        type=str,
        required=False,
        help="Output JSON file name (in data/knowledge/<lang>/ if --lang is set, else data/knowledge/). "
             "If omitted in single-file mode, defaults to <input_stem>_knowledge.json"
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        help="Process all CWE JSON files in data/train/<lang>/ (or recursively under data/train/ if --lang omitted)"
    )
    parser.add_argument(
        "--model_name",
        type=str,
        required=True,
        help="LLM model name (e.g., gpt-4o-mini, gpt-4o, gpt-4-turbo)"
    )
    parser.add_argument(
        '--model_settings',
        type=str,
        default=None,
        help='Model settings in key-value format: "temperature=0.2;max_tokens=1024"'
    )
    parser.add_argument(
        '--thread_pool_size',
        type=int,
        default=5,
        help="Number of parallel threads for processing"
    )
    parser.add_argument(
        '--retry_time',
        type=int,
        default=5,
        help="Number of retries on API failure"
    )
    parser.add_argument(
        '--resume',
        action='store_true',
        help='Resume from checkpoint if exists'
    )
    args = parser.parse_args()
    args.model_settings = llm_client.parse_kv_string_to_dict(args.model_settings)
    return args


def get_train_base_dir(lang: str | None) -> Path:
    base = Path("data/train")
    return base / lang if lang else base


def get_knowledge_base_dir(lang: str | None) -> Path:
    base = Path("data/knowledge")
    return base / lang if lang else base


def build_output_file_name(input_file_name: str) -> str:
    p = Path(input_file_name)
    return f"{p.stem}_knowledge.json"


def is_cwe_json_file(path: Path) -> bool:
    return path.is_file() and path.suffix == ".json" and path.name.startswith("CWE-")


def generate_extract_prompt(cve_id, cve_description, modified_lines, code_before, code_after):
    """
    단계별 프롬프트 생성 (src/prompts/extract_knowledge.yaml 기반)

    Returns:
        tuple: (purpose_prompt, function_prompt, analysis_prompt, knowledge_extraction_prompt)
    """
    t = _load_prompts()

    prefix = t["prefix"].format_map({
        "cve_id": cve_id,
        "code_before": code_before,
        "cve_description": cve_description,
    })

    purpose_prompt = t["purpose"].format_map({"prefix": prefix})
    function_prompt = t["function_summary"].format_map({"prefix": prefix})

    analysis_prompt = t["analysis_base"].format_map({
        "prefix": prefix,
        "modified_lines_json": json.dumps(modified_lines, indent=2),
    })
    if modified_lines.get("added"):
        analysis_prompt += t["analysis_code_after"].format_map({"code_after": code_after})
    analysis_prompt += t["analysis_suffix"]

    knowledge_extraction_prompt = t["knowledge_extraction"]

    return purpose_prompt, function_prompt, analysis_prompt, knowledge_extraction_prompt


def parse_vulnerability_knowledge(llm_output: str) -> Dict[str, Any]:
    """
    LLM 출력에서 vulnerability_behavior JSON 추출
    """
    try:
        if "```json" in llm_output:
            llm_output = llm_output.split("```json")[1].split("```")[0]
        elif "```" in llm_output:
            llm_output = llm_output.split("```")[1].split("```")[0]

        if "\"vulnerability_behavior\"" in llm_output:
            llm_output = llm_output.split("\"vulnerability_behavior\"")[1]
            llm_output = "{\"vulnerability_behavior\"" + llm_output

        if "\n```" in llm_output:
            llm_output = llm_output.split("\n```")[0]

        return json.loads(llm_output)
    except Exception as e:
        print(f"Error parsing LLM output: {e}")
        print(f"Output: {llm_output[:200]}...")
        raise


def extract_knowledge(args, item: Dict[str, Any], output_data: List[Dict[str, Any]], custom_output_file=None) -> None:
    """
    단일 CVE 항목에 대해 지식 추출
    """
    try:
        global MODEL_CLIENT

        def generate_with_retry(prompt_dict, settings):
            last_exception = None
            for attempt in range(args.retry_time):
                try:
                    return MODEL_CLIENT.generate_text(prompt_dict, settings)
                except Exception as e:
                    last_exception = e
                    if attempt < args.retry_time - 1:
                        print(f"[{item['cve_id']}] Attempt {attempt + 1}/{args.retry_time} failed: {str(e)}")
                        time.sleep(1.0)
                    continue
            raise last_exception

        purpose_prompt, function_prompt, analysis_prompt, knowledge_extraction_prompt = generate_extract_prompt(
            item["cve_id"],
            item["cve_description"],
            item["function_modified_lines"],
            item["code_before_change"],
            item["code_after_change"]
        )

        purpose_prompt_dict = llm_client.generate_simple_prompt(purpose_prompt)
        purpose_output = generate_with_retry(purpose_prompt_dict, args.model_settings)

        function_prompt_dict = llm_client.generate_simple_prompt(function_prompt)
        function_output = generate_with_retry(function_prompt_dict, args.model_settings)

        messages = llm_client.generate_simple_prompt(analysis_prompt)
        analysis_output = generate_with_retry(messages, args.model_settings)

        messages.append({"role": "assistant", "content": analysis_output})
        messages.append({"role": "user", "content": knowledge_extraction_prompt})
        knowledge_extraction_output = generate_with_retry(messages, args.model_settings)

        raw_dict = parse_vulnerability_knowledge(knowledge_extraction_output)

        solution = raw_dict.get("solution", "")
        vb_raw = raw_dict.get("vulnerability_behavior", {})
        if not solution and "solution" in vb_raw:
            solution = vb_raw.pop("solution")

        vulnerability_behavior = VulnerabilityBehavior(
            vulnerability_cause_description=vb_raw.get("vulnerability_cause_description", ""),
            trigger_condition=vb_raw.get("trigger_condition", ""),
            specific_code_behavior_causing_vulnerability=vb_raw.get("specific_code_behavior_causing_vulnerability", ""),
        )

        knowledge_dto = VulnerabilityKnowledgeDTO(
            CVE_id=item["cve_id"],
            vulnerability_behavior=vulnerability_behavior,
            solution=solution,
            purpose=llm_client.extract_LLM_response_by_prefix(purpose_output, "Function purpose:"),
            function=llm_client.extract_LLM_response_by_prefix(function_output, "The functions of the code snippet are:"),
            analysis=analysis_output,
            code_before_change=item["code_before_change"],
            code_after_change=item["code_after_change"],
            modified_lines=item["function_modified_lines"],
            vulnerability_cause_description=vulnerability_behavior.vulnerability_cause_description,
            trigger_condition=vulnerability_behavior.trigger_condition,
            specific_code_behavior_causing_vulnerability=vulnerability_behavior.specific_code_behavior_causing_vulnerability,
        )
        output_dict = knowledge_dto.model_dump()

        with output_lock:
            output_data.append(output_dict)
            with file_lock:
                actual_output_name = custom_output_file or args.output_file_name
                output_path = get_knowledge_base_dir(args.lang) / actual_output_name
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(output_data, f, indent=4, ensure_ascii=False)

        print(f"✓ Processed {item['cve_id']}")

    except Exception as e:
        print(f"✗ Error processing {item['cve_id']}: {str(e)}")
        return


def process_item(args, item: Dict[str, Any], output_data: List[Dict[str, Any]], resume_set: set, custom_output_file=None):
    """개별 아이템 처리"""
    if item["cve_id"] not in resume_set:
        extract_knowledge(args, item, output_data, custom_output_file)
    else:
        print(f"⊙ Skipping {item['cve_id']} (already processed)")


def run_batch_pipeline(args):
    """데이터 디렉토리 전체를 처리하는 배치 파이프라인"""
    input_dir = get_train_base_dir(args.lang)
    if not input_dir.exists():
        print(f"Error: Input directory not found: {input_dir}")
        return

    if args.lang:
        json_files = sorted([p for p in input_dir.glob("*.json") if is_cwe_json_file(p)])
    else:
        json_files = sorted([p for p in input_dir.rglob("*.json") if is_cwe_json_file(p)])

    print(f"Found {len(json_files)} CWE files in {input_dir}")

    all_items = []
    file_map = {}  # cve_id -> output_filename

    for f_path in json_files:
        try:
            with open(f_path, "r", encoding="utf-8") as f:
                items = json.load(f)
                out_name = f_path.name.replace(".json", "_knowledge.json")
                for item in items:
                    all_items.append(item)
                    file_map[item["cve_id"]] = out_name
        except Exception as e:
            print(f"Failed to load {f_path}: {e}")

    if not all_items:
        print("No items to process.")
        return

    unique_out_names = set(file_map.values())
    output_data_map = {out_name: [] for out_name in unique_out_names}
    resume_sets = {out_name: set() for out_name in unique_out_names}

    if args.resume:
        for out_name in unique_out_names:
            output_path = get_knowledge_base_dir(args.lang) / out_name
            if output_path.exists():
                try:
                    with open(output_path, "r", encoding="utf-8") as f:
                        existing = json.load(f)
                        output_data_map[out_name] = existing
                        resume_sets[out_name] = set(item["CVE_id"] for item in existing)
                    print(f"Resuming {out_name}: {len(resume_sets[out_name])} already processed")
                except Exception as e:
                    print(f"Failed to load resume data for {out_name}: {e}")

    total_resume = sum(len(s) for s in resume_sets.values())
    if total_resume:
        print(f"Resuming: {total_resume} items already processed")

    print(f"Processing {len(all_items)} items across {len(json_files)} files...")
    with ThreadPoolExecutor(max_workers=args.thread_pool_size) as executor:
        list(tqdm(
            executor.map(
                lambda item: process_item(
                    args,
                    item,
                    output_data_map[file_map[item["cve_id"]]],
                    resume_sets[file_map[item["cve_id"]]],
                    custom_output_file=file_map[item["cve_id"]]
                ),
                all_items
            ),
            total=len(all_items),
            desc="Batch Knowledge Extraction"
        ))


def extract_knowledge_pipeline(args):
    """메인 파이프라인"""
    global MODEL_CLIENT

    try:
        MODEL_CLIENT = llm_client.get_llm_client(args.model_name)
        print(f"Initialized LLM Client: {MODEL_CLIENT.model_name}")
    except Exception as e:
        print(f"Failed to initialize LLM client: {e}")
        sys.exit(1)

    if args.batch:
        run_batch_pipeline(args)
        return

    if not args.input_file_name:
        print("Error: --input_file_name is required unless --batch is used.")
        sys.exit(1)

    if not args.output_file_name:
        args.output_file_name = build_output_file_name(args.input_file_name)

    input_path = get_train_base_dir(args.lang) / args.input_file_name
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    print(f"Loaded {len(data)} items from {input_path}")

    output_data = []
    resume_set = set()

    if args.resume:
        output_path = get_knowledge_base_dir(args.lang) / args.output_file_name
        if output_path.exists():
            with open(output_path, "r", encoding="utf-8") as f:
                output_data = json.load(f)
                resume_set = set(item["CVE_id"] for item in output_data)
            print(f"Resuming: Found {len(resume_set)} already processed items")

    print(f"Processing with {args.thread_pool_size} threads...")
    with ThreadPoolExecutor(max_workers=args.thread_pool_size) as executor:
        list(tqdm(
            executor.map(
                lambda item: process_item(args, item, output_data, resume_set),
                data
            ),
            total=len(data),
            desc="Extracting Knowledge"
        ))

    print(f"\n✓ Complete! Processed {len(output_data)} items")
    print(f"  Output: {get_knowledge_base_dir(args.lang) / args.output_file_name}")


if __name__ == "__main__":
    args = parse_args()
    extract_knowledge_pipeline(args)