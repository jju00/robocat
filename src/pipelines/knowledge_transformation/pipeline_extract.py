"""
Knowledge Extraction Pipeline
RawDiffDTO JSON → LLM 분석 → VulnerabilityKnowledgeDTO JSON

Usage:
    python src/pipelines/pipeline_extract.py \
        --input_file_name CVE-2021-3904.json \
        --output_file_name CVE-2021-3904_knowledge.json \       # 기본값 - input file에 +_knowledge.json 붙여서 저장 
        --model_name gpt-4o-mini \                              # 이미 llm_client에서 정의된 모델이 mini
        --model_settings "temperature=0.2;max_tokens=4096" \    # 여기도 llm_client에 기본값 존재 
        --thread_pool_size 5 \
        --retry_time 3 \
        --resume \                                               # 이미 처리된 데이터 건너뛰기 
        --batch                                                  # 전체 데이터 처리
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
    parser.add_argument("--input_file_name", type=str, required=False, 
                       help="Input JSON file name (in data/train/)")
    parser.add_argument("--output_file_name", type=str, required=False,
                       help="Output JSON file name (in data/knowledge/)")
    parser.add_argument("--batch", action="store_true",
                       help="Process all files in data/train/")
    parser.add_argument("--model_name", type=str, required=True,
                       help="LLM model name (e.g., gpt-4o-mini, gpt-4o, gpt-4-turbo)")
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


def generate_extract_prompt(cve_id, cve_description, modified_lines, code_before, code_after):
    """
    단계별 프롬프트 생성 (src/prompts/extract_knowledge.yaml 기반)

    Returns:
        tuple: (purpose_prompt, function_prompt, analysis_prompt, knowledge_extraction_prompt)
    """
    t = _load_prompts()

    # 공통 prefix 렌더링
    prefix = t["prefix"].format_map({
        "cve_id": cve_id,
        "code_before": code_before,
        "cve_description": cve_description,
    })

    # Step 1: Extract purpose
    purpose_prompt = t["purpose"].format_map({"prefix": prefix})

    # Step 2: Extract function summary
    function_prompt = t["function_summary"].format_map({"prefix": prefix})

    # Step 3: Extract analysis (조건부 code_after 포함)
    analysis_prompt = t["analysis_base"].format_map({
        "prefix": prefix,
        "modified_lines_json": json.dumps(modified_lines, indent=2),
    })
    if modified_lines.get("added"):
        analysis_prompt += t["analysis_code_after"].format_map({"code_after": code_after})
    analysis_prompt += t["analysis_suffix"]

    # Step 4: Knowledge extraction (변수 없음, 그대로 사용)
    knowledge_extraction_prompt = t["knowledge_extraction"]

    return purpose_prompt, function_prompt, analysis_prompt, knowledge_extraction_prompt


def parse_vulnerability_knowledge(llm_output: str) -> Dict[str, Any]:
    """
    LLM 출력에서 vulnerability_behavior JSON 추출
    """
    try:
        # JSON 블록 찾기
        if "```json" in llm_output:
            llm_output = llm_output.split("```json")[1].split("```")[0]
        elif "```" in llm_output:
            llm_output = llm_output.split("```")[1].split("```")[0]
        
        # vulnerability_behavior 찾기
        if "\"vulnerability_behavior\"" in llm_output:
            llm_output = llm_output.split("\"vulnerability_behavior\"")[1]
            llm_output = "{\"vulnerability_behavior\"" + llm_output
        
        # 정리
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
            """재시도 로직이 포함된 생성 함수"""
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

        # 프롬프트 생성
        purpose_prompt, function_prompt, analysis_prompt, knowledge_extraction_prompt = generate_extract_prompt(
            item["cve_id"], 
            item["cve_description"], 
            item["function_modified_lines"], 
            item["code_before_change"], 
            item["code_after_change"]
        )

        # Step 1: Extract Purpose
        purpose_prompt_dict = llm_client.generate_simple_prompt(purpose_prompt)
        purpose_output = generate_with_retry(purpose_prompt_dict, args.model_settings)

        # Step 2: Extract Function Summary
        function_prompt_dict = llm_client.generate_simple_prompt(function_prompt)
        function_output = generate_with_retry(function_prompt_dict, args.model_settings)

        # Step 3: Extract Analysis
        messages = llm_client.generate_simple_prompt(analysis_prompt)
        analysis_output = generate_with_retry(messages, args.model_settings)

        # Step 4: Extract Vulnerability Knowledge
        messages.append({"role": "assistant", "content": analysis_output})
        messages.append({"role": "user", "content": knowledge_extraction_prompt})
        knowledge_extraction_output = generate_with_retry(messages, args.model_settings)

        # Parse LLM output
        raw_dict = parse_vulnerability_knowledge(knowledge_extraction_output)

        # solution 처리: LLM이 vulnerability_behavior 내에 넣은 경우 꺼내기
        solution = raw_dict.get("solution", "")
        vb_raw = raw_dict.get("vulnerability_behavior", {})
        if not solution and "solution" in vb_raw:
            solution = vb_raw.pop("solution")

        # VulnerabilityBehavior 생성
        vulnerability_behavior = VulnerabilityBehavior(
            vulnerability_cause_description=vb_raw.get("vulnerability_cause_description", ""),
            trigger_condition=vb_raw.get("trigger_condition", ""),
            specific_code_behavior_causing_vulnerability=vb_raw.get("specific_code_behavior_causing_vulnerability", ""),
        )

        # VulnerabilityKnowledgeDTO로 유효성 검사 후 직렬화
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

        # Thread-safe output
        with output_lock:
            # 배치 모드일 경우 각 파일마다 별도 처리하거나 리스트에 추가
            output_data.append(output_dict)
            with file_lock:
                actual_output_name = custom_output_file or args.output_file_name
                output_path = Path("data/knowledge") / actual_output_name
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
    input_dir = Path("data/train")
    if not input_dir.exists():
        print(f"Error: Input directory not found: {input_dir}")
        return

    json_files = list(input_dir.glob("*.json"))
    print(f"Found {len(json_files)} files in {input_dir}")

    # 모든 아이템을 하나의 리스트로 통합하여 병렬 처리
    all_items = []
    file_map = {}  # cve_id -> output_filename

    for f_path in json_files:
        try:
            with open(f_path, "r", encoding="utf-8") as f:
                items = json.load(f)
                out_name = f_path.name.replace(".json", "_knowledge.json")
                for item in items:
                    all_items.append(item)
                    file_map[item["cve_id"]] = out_name  # cve_id 기준으로 매핑
        except Exception as e:
            print(f"Failed to load {f_path}: {e}")

    if not all_items:
        print("No items to process.")
        return

    # CWE 파일별 output_data 공유 딕셔너리 (덮어쓰기 방지)
    unique_out_names = set(file_map.values())
    output_data_map = {out_name: [] for out_name in unique_out_names}
    resume_sets = {out_name: set() for out_name in unique_out_names}

    # Resume 처리: 기존 knowledge 파일에서 cve_id 로드
    if args.resume:
        for out_name in unique_out_names:
            output_path = Path("data/knowledge") / out_name
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
    
    # LLM 클라이언트 초기화
    try:
        MODEL_CLIENT = llm_client.get_llm_client(args.model_name)
        print(f"Initialized LLM Client: {MODEL_CLIENT.model_name}")
    except Exception as e:
        print(f"Failed to initialize LLM client: {e}")
        sys.exit(1)
    
    if args.batch:
        run_batch_pipeline(args)
        return

    if not args.input_file_name or not args.output_file_name:
        print("Error: --input_file_name and --output_file_name are required unless --batch is used.")
        sys.exit(1)

    # 입력 데이터 로드
    input_path = Path("data/train") / args.input_file_name
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        sys.exit(1)
    
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    print(f"Loaded {len(data)} items from {input_path}")
    
    # Resume 처리
    output_data = []
    resume_set = set()
    
    if args.resume:
        output_path = Path("data/knowledge") / args.output_file_name
        if output_path.exists():
            with open(output_path, "r", encoding="utf-8") as f:
                output_data = json.load(f)
                resume_set = set(item["CVE_id"] for item in output_data)
            print(f"Resuming: Found {len(resume_set)} already processed items")
    
    # 병렬 처리
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
    print(f"  Output: data/knowledge/{args.output_file_name}")


if __name__ == "__main__":
    args = parse_args()
    extract_knowledge_pipeline(args)
