import json
import os
import sys
import argparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import utils.bm25_retriever as bm25_retriever

# 캐시용 변수 - bm25 인덱스 및 지식 데이터 저장 
GLOBAL_CODE_RETRIEVER = None
GLOBAL_KNOWLEDGE_DATA = None

# cli 인자 파싱 
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--input_file_name", type=str, required=True)      # data/test/xxx.json
    p.add_argument("--knowledge_file_name", type=str, required=True)  # output/knowledge/xxx.json
    p.add_argument("--output_file_name", type=str, required=True)     # output/retrieval/xxx.json
    p.add_argument("--retrieval_top_k", type=int, default=20)
    p.add_argument("--dedup_by_cve", action="store_true",
                   help="If set, return at most top_k unique CVE items (deduplicate by CVE_id).")
    return p.parse_args()


##################### retriever initialization ##########################
# 지식 데이터 로드 및 bm25 인덱스 생성 (knowledge 로드 + 코퍼스 인덱싱)
def init_retriever(knowledge_path: str):
    global GLOBAL_CODE_RETRIEVER, GLOBAL_KNOWLEDGE_DATA

    with open(knowledge_path, "r") as f:
        GLOBAL_KNOWLEDGE_DATA = json.load(f)     # knowledge 데이터 로드

    code_list = [item["code_before_change"] for item in GLOBAL_KNOWLEDGE_DATA]      # code_before_change만 뽑은 리스트 
    GLOBAL_CODE_RETRIEVER = bm25_retriever.BM25Retriever()                          # BM25 인스턴스 생성 (utils/bm25_retriever.py 에서 정의)
    GLOBAL_CODE_RETRIEVER.set_corpus(code_list)

def retrieve_top_k_by_code(query_code: str, top_k: int, dedup_by_cve: bool):
    idxs = GLOBAL_CODE_RETRIEVER.search(query_code, top_n=top_k if not dedup_by_cve else -1)

    results = []
    seen_cves = set()

    for idx in idxs:
        item = GLOBAL_KNOWLEDGE_DATA[idx]
        cve_id = item.get("CVE_id")

        if dedup_by_cve:
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)

        results.append({
            "knowledge_index": idx,
            "cve_id": cve_id,
            "code_before_change": item.get("code_before_change"),
            "code_after_change": item.get("code_after_change"),
            # 필요하면 아래도 추가 가능:
            # "purpose": item.get("purpose"),
            # "function": item.get("function"),
            # "vulnerability_cause_description": item.get("vulnerability_cause_description"),
            # "trigger_condition": item.get("trigger_condition"),
            # "specific_code_behavior_causing_vulnerability": item.get("specific_code_behavior_causing_vulnerability"),
            # "solution": item.get("solution"),
        })

        if len(results) >= top_k:
            break

    return results

def main():
    args = parse_args()

    knowledge_path = f"../data/knowledge/{args.knowledge_file_name}"      # 지식 데이터 경로
    input_path = f"../data/test/{args.input_file_name}"                      # TC 경로 (릴리즈 diff)
    output_path = f"../data/retrieval/{args.output_file_name}"            # 결과 저장 경로 

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    init_retriever(knowledge_path)

    with open(input_path, "r") as f:
        test_data = json.load(f)

    out = []
    for item in test_data:
        code_before = item["code_before_change"]
        code_after = item["code_after_change"]

        out.append({
            "id": item.get("id"),
            "cve_id": item.get("cve_id"),
            "retrieved_before": retrieve_top_k_by_code(code_before, args.retrieval_top_k, args.dedup_by_cve),
            "retrieved_after": retrieve_top_k_by_code(code_after, args.retrieval_top_k, args.dedup_by_cve),
        })

    with open(output_path, "w") as f:
        json.dump(out, f, indent=4)

if __name__ == "__main__":
    main()