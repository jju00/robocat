"""
2-Stage Retriever
=================
Stage 1: knowledge의 purpose / function / full_code 3개 필드에 대해 각각 BM25 검색 후
         rank sum으로 전체 item 랭킹 계산
Stage 2: CVE 단위로 rank sum 최소 item 1개만 선택 → top-k CVE 반환

입력 쿼리: 타겟 코드의 purpose, function, full_code
출력:      List[RetrievedKnowledgeDTO]
"""
import json
import os
import argparse
from typing import Optional, List, Dict, Tuple

from ...utils.bm25_retriever import BM25Retriever
from ...dto.retriever_output_dto import RetrievedKnowledgeDTO, VulnerabilityBehaviorDTO


# ─── 전역 캐시 ──────────────────────────────────────────────────────────────────
GLOBAL_KNOWLEDGE_DATA: Optional[List[dict]] = None

# 3개 필드별 BM25 인덱스
#   - purpose    : 함수의 목적 요약
#   - function   : 함수의 동작 절차 요약
#   - full_code  : 원본 함수 전체 코드 (추후 LLM scope 요약 파일을 통해 채워짐)
RETRIEVER_PURPOSE: Optional[BM25Retriever] = None
RETRIEVER_FUNCTION: Optional[BM25Retriever] = None
RETRIEVER_FULL_CODE: Optional[BM25Retriever] = None

# 각 인덱스 활성 여부 (코퍼스 전체가 빈 문자열이면 비활성화)
_ACTIVE_FIELDS: Dict[str, bool] = {
    "purpose": False,
    "function": False,
    "full_code": False,
}


# ─── CLI ────────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--input_file_name",     type=str, required=True)   # data/test/xxx.json
    p.add_argument("--knowledge_file_name", type=str, required=True)   # data/knowledge/xxx.json
    p.add_argument("--output_file_name",    type=str, required=True)   # data/retrieval/xxx.json
    p.add_argument("--retrieval_top_k",     type=int, default=20)
    return p.parse_args()


##################### retriever initialization ##########################
# 지식 데이터 로드 및 bm25 인덱스 생성 (knowledge 로드 + 코퍼스 인덱싱)
def _build_retriever(corpus: List[str]) -> Tuple[BM25Retriever, bool]:
    """코퍼스로 BM25Retriever를 빌드하고, 유효 항목이 있는지 여부를 함께 반환."""
    is_active = any(text.strip() for text in corpus)
    retriever = BM25Retriever()
    retriever.set_corpus(corpus)
    return retriever, is_active


def init_retriever(knowledge_path: str):
    """
    knowledge JSON 파일을 로드하고 purpose / function / full_code 3개의
    BM25 인덱스를 생성한다.

    full_code 필드는 추후 LLM scope 요약 파일이 생성된 후 knowledge에 포함되면
    자동으로 인덱싱된다.  현재 없는 경우에는 해당 인덱스를 비활성화한다.
    """
    global GLOBAL_KNOWLEDGE_DATA
    global RETRIEVER_PURPOSE, RETRIEVER_FUNCTION, RETRIEVER_FULL_CODE
    global _ACTIVE_FIELDS

    with open(knowledge_path, "r", encoding="utf-8") as f:
        GLOBAL_KNOWLEDGE_DATA = json.load(f)

    purpose_corpus   = [item.get("purpose",   "") or "" for item in GLOBAL_KNOWLEDGE_DATA]
    function_corpus  = [item.get("function",  "") or "" for item in GLOBAL_KNOWLEDGE_DATA]
    full_code_corpus = [item.get("full_code", "") or "" for item in GLOBAL_KNOWLEDGE_DATA]

    RETRIEVER_PURPOSE,   _ACTIVE_FIELDS["purpose"]   = _build_retriever(purpose_corpus)
    RETRIEVER_FUNCTION,  _ACTIVE_FIELDS["function"]  = _build_retriever(function_corpus)
    RETRIEVER_FULL_CODE, _ACTIVE_FIELDS["full_code"] = _build_retriever(full_code_corpus)


# ─── Stage 1: Rank Sum ───────────────────────────────────────────────────────────
def _compute_rank_sum(
    query_purpose:   Optional[str],
    query_function:  Optional[str],
    query_full_code: Optional[str],
) -> List[int]:
    """
    활성화된 각 필드에 대해 BM25 검색을 수행하고
    item별 rank sum 배열을 반환한다 (값이 낮을수록 관련성 높음).
    """
    n = len(GLOBAL_KNOWLEDGE_DATA)
    rank_sum = [0] * n

    field_queries = [
        ("purpose",   query_purpose,   RETRIEVER_PURPOSE),
        ("function",  query_function,  RETRIEVER_FUNCTION),
        ("full_code", query_full_code, RETRIEVER_FULL_CODE),
    ]

    for field_name, query_text, retriever in field_queries:
        if not _ACTIVE_FIELDS[field_name]:
            continue
        if not query_text or not query_text.strip():
            continue

        sorted_idxs = retriever.search(query_text, top_n=-1)
        for rank, idx in enumerate(sorted_idxs):
            rank_sum[idx] += rank + 1   # rank는 1-based (낮을수록 좋음)

    return rank_sum


# ─── Stage 2: CVE별 best item 선택 → top-k ────────────────────────────────────
def retrieve_top_k(
    query_purpose:   Optional[str],
    query_function:  Optional[str],
    query_full_code: Optional[str],
    top_k: int,
) -> List[RetrievedKnowledgeDTO]:
    """
    Stage 1: rank sum으로 전체 item 정렬
    Stage 2: CVE_id별로 rank sum이 가장 낮은 item 1개 선택 (best representative)
             → 상위 top_k CVE를 RetrievedKnowledgeDTO 리스트로 반환
    """
    rank_sum = _compute_rank_sum(query_purpose, query_function, query_full_code)

    # rank sum 오름차순으로 item 인덱스 정렬
    sorted_indices = sorted(range(len(GLOBAL_KNOWLEDGE_DATA)), key=lambda i: rank_sum[i])

    # Stage 2: CVE 단위 dedup — 각 CVE에서 처음(= rank sum 최소) item만 보존
    seen_cves: Dict[str, Tuple[int, int]] = {}   # CVE_id → (item_idx, rank_sum)
    for idx in sorted_indices:
        cve_id = GLOBAL_KNOWLEDGE_DATA[idx].get("CVE_id")
        if cve_id and cve_id not in seen_cves:
            seen_cves[cve_id] = (idx, rank_sum[idx])

    # CVE 대표 item을 rank sum 기준 재정렬 후 top-k 선택
    top_cves = sorted(seen_cves.values(), key=lambda t: t[1])[:top_k]

    results: List[RetrievedKnowledgeDTO] = []
    for item_idx, _ in top_cves:
        item = GLOBAL_KNOWLEDGE_DATA[item_idx]
        dto = RetrievedKnowledgeDTO(
            cve_id=item.get("CVE_id", ""),
            vulnerability_behavior=VulnerabilityBehaviorDTO(
                vulnerability_cause_description=item.get("vulnerability_cause_description", ""),
                trigger_condition=item.get("trigger_condition", ""),
                specific_code_behavior_causing_vulnerability=item.get("specific_code_behavior_causing_vulnerability", ""),
            ),
            solution_behavior=item.get("solution", ""),
        )
        results.append(dto)

    return results


# ─── main ────────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()

    knowledge_path = f"../data/knowledge/{args.knowledge_file_name}"
    input_path     = f"../data/test/{args.input_file_name}"
    output_path    = f"../data/retrieval/{args.output_file_name}"

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    init_retriever(knowledge_path)

    with open(input_path, "r", encoding="utf-8") as f:
        test_data = json.load(f)

    out = []
    for item in test_data:
        # 타겟 코드의 purpose / function / full_code 쿼리
        # (추후 LLM scope 분석 결과가 이 필드에 채워짐 — 현재 없으면 None 처리)
        query_purpose   = item.get("purpose")
        query_function  = item.get("function")
        query_full_code = item.get("full_code")

        retrieved = retrieve_top_k(
            query_purpose   = query_purpose,
            query_function  = query_function,
            query_full_code = query_full_code,
            top_k           = args.retrieval_top_k,
        )

        out.append({
            "id":        item.get("id"),
            "cve_id":    item.get("cve_id"),
            "retrieved": [r.model_dump() for r in retrieved],
        })

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=4, ensure_ascii=False)


if __name__ == "__main__":
    main()
