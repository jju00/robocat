import json
import os
import argparse
from typing import Optional, List

from ...utils.bm25_retriever import BM25Retriever
from ...dto.retriever_output_dto import RetrievedKnowledgeDTO, VulnerabilityBehaviorDTO

# 캐시용 변수 - bm25 인덱스 및 지식 데이터 저장
GLOBAL_CODE_RETRIEVER: Optional[BM25Retriever] = None
GLOBAL_KNOWLEDGE_DATA: Optional[list] = None
# 외부 scope 요약 파일 기반 CVE_id → {purpose, function} 매핑
# (추후 LLM이 llm_scope_functions.json을 요약해 생성하는 파일에서 로드)
GLOBAL_SCOPE_MAP: Optional[dict] = None


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--input_file_name", type=str, required=True)       # data/test/xxx.json
    p.add_argument("--knowledge_file_name", type=str, required=True)   # data/knowledge/xxx.json
    p.add_argument("--output_file_name", type=str, required=True)      # data/retrieval/xxx.json
    p.add_argument("--scope_file_name", type=str, default=None,
                   help="Optional: scope summary JSON file (purpose/function per CVE_id). "
                        "Generated externally by LLM summarization of llm_scope_functions.json.")
    p.add_argument("--retrieval_top_k", type=int, default=20)
    p.add_argument("--dedup_by_cve", action="store_true",
                   help="If set, return at most top_k unique CVE items (deduplicate by CVE_id).")
    return p.parse_args()


##################### retriever initialization ##########################
# 지식 데이터 로드 및 bm25 인덱스 생성 (knowledge 로드 + 코퍼스 인덱싱)
def init_retriever(knowledge_path: str, scope_path: Optional[str] = None):
    global GLOBAL_CODE_RETRIEVER, GLOBAL_KNOWLEDGE_DATA, GLOBAL_SCOPE_MAP

    with open(knowledge_path, "r") as f:
        GLOBAL_KNOWLEDGE_DATA = json.load(f)

    code_list = [item["code_before_change"] for item in GLOBAL_KNOWLEDGE_DATA]
    GLOBAL_CODE_RETRIEVER = BM25Retriever()
    GLOBAL_CODE_RETRIEVER.set_corpus(code_list)

    # 외부 scope 요약 파일 로드: {CVE_id: {purpose, function}}
    # 파일이 존재하지 않으면 빈 dict로 처리 (purpose/function = None으로 유지)
    if scope_path and os.path.exists(scope_path):
        with open(scope_path, "r") as f:
            scope_data = json.load(f)
        GLOBAL_SCOPE_MAP = {item["CVE_id"]: item for item in scope_data}
    else:
        GLOBAL_SCOPE_MAP = {}


def retrieve_top_k_by_code(
    query_code: str,
    top_k: int,
    dedup_by_cve: bool
) -> List[RetrievedKnowledgeDTO]:
    idxs = GLOBAL_CODE_RETRIEVER.search(query_code, top_n=top_k if not dedup_by_cve else -1)

    results: List[RetrievedKnowledgeDTO] = []
    seen_cves = set()

    for idx in idxs:
        item = GLOBAL_KNOWLEDGE_DATA[idx]
        cve_id = item.get("CVE_id")

        if dedup_by_cve:
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)

        # 외부 scope 요약 파일에서 purpose, function 가져오기
        scope_info = GLOBAL_SCOPE_MAP.get(cve_id, {})

        dto = RetrievedKnowledgeDTO(
            cve_id=cve_id,
            vulnerability_behavior=VulnerabilityBehaviorDTO(
                vulnerability_cause_description=item.get("vulnerability_cause_description", ""),
                trigger_condition=item.get("trigger_condition", ""),
                specific_code_behavior_causing_vulnerability=item.get("specific_code_behavior_causing_vulnerability", ""),
            ),
            solution_behavior=item.get("solution", ""),
            purpose=scope_info.get("purpose"),
            function=scope_info.get("function"),
        )
        results.append(dto)

        if len(results) >= top_k:
            break

    return results


def main():
    args = parse_args()

    knowledge_path = f"../data/knowledge/{args.knowledge_file_name}"
    input_path = f"../data/test/{args.input_file_name}"
    output_path = f"../data/retrieval/{args.output_file_name}"
    scope_path = f"../data/scope/{args.scope_file_name}" if args.scope_file_name else None

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    init_retriever(knowledge_path, scope_path=scope_path)

    with open(input_path, "r") as f:
        test_data = json.load(f)

    out = []
    for item in test_data:
        code_before = item["code_before_change"]
        code_after = item["code_after_change"]

        retrieved_before = retrieve_top_k_by_code(code_before, args.retrieval_top_k, args.dedup_by_cve)
        retrieved_after = retrieve_top_k_by_code(code_after, args.retrieval_top_k, args.dedup_by_cve)

        out.append({
            "id": item.get("id"),
            "cve_id": item.get("cve_id"),
            "retrieved_before": [r.model_dump() for r in retrieved_before],
            "retrieved_after": [r.model_dump() for r in retrieved_after],
        })

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=4, ensure_ascii=False)


if __name__ == "__main__":
    main()
