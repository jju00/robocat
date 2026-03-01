"""
2-Stage Retriever
=================
Stage 1: knowledge의 3개 코퍼스 필드에 대해 각각 BM25 검색 후 rank sum으로 전체 item 랭킹 계산
         쿼리 (diff_retriever.json)         ↔  코퍼스 (knowledge)
         ──────────────────────────────────────────────────────
         full_code       (원본 함수 전체코드) ↔  code_before_change
         purpose         (함수 목적 요약)     ↔  purpose
         function_summary (함수 동작 요약)    ↔  function
Stage 2: CVE 단위로 rank sum 최소 item 1개만 선택 → top-k CVE 반환

입력 쿼리: diff_retriever.json 항목의 full_code / purpose / function_summary
출력:      List[RetrievedKnowledgeDTO]
"""
import json
import os
import sys
import argparse
from pathlib import Path
from typing import Optional, List, Dict, Tuple

# 패키지 내 import (python -m) / 직접 실행 (python3 src/...) 양쪽 지원
try:
    from ...utils.bm25_retriever import BM25Retriever
    from ...dto.retriever_output_dto import RetrievedKnowledgeDTO, VulnerabilityBehaviorDTO
except ImportError:
    _ROOT = Path(__file__).resolve().parents[3]   # NLD/
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))
    from src.utils.bm25_retriever import BM25Retriever
    from src.dto.retriever_output_dto import RetrievedKnowledgeDTO, VulnerabilityBehaviorDTO


# ─── 전역 캐시 ──────────────────────────────────────────────────────────────────
GLOBAL_KNOWLEDGE_DATA: Optional[List[dict]] = None

# 3개 필드별 BM25 인덱스 (코퍼스는 knowledge 기준)
#   - purpose      : knowledge.purpose
#   - function     : knowledge.function
#   - code_before  : knowledge.code_before_change
RETRIEVER_PURPOSE: Optional[BM25Retriever] = None
RETRIEVER_FUNCTION: Optional[BM25Retriever] = None
RETRIEVER_CODE_BEFORE: Optional[BM25Retriever] = None

# 각 인덱스 활성 여부 (코퍼스 전체가 빈 문자열이면 비활성화)
_ACTIVE_FIELDS: Dict[str, bool] = {
    "purpose":      False,
    "function":     False,
    "code_before":  False,
}


# ─── CLI ────────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--input_file_name",     type=str, required=True)   # data/test/diff_retriever.json
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
    knowledge JSON 파일을 로드하고 3개의 BM25 인덱스를 생성한다.

    코퍼스 필드 매핑:
        RETRIEVER_PURPOSE      ← knowledge.purpose
        RETRIEVER_FUNCTION     ← knowledge.function
        RETRIEVER_CODE_BEFORE  ← knowledge.code_before_change
    """
    global GLOBAL_KNOWLEDGE_DATA
    global RETRIEVER_PURPOSE, RETRIEVER_FUNCTION, RETRIEVER_CODE_BEFORE
    global _ACTIVE_FIELDS

    with open(knowledge_path, "r", encoding="utf-8") as f:
        GLOBAL_KNOWLEDGE_DATA = json.load(f)

    purpose_corpus      = [item.get("purpose",            "") or "" for item in GLOBAL_KNOWLEDGE_DATA]
    function_corpus     = [item.get("function",           "") or "" for item in GLOBAL_KNOWLEDGE_DATA]
    code_before_corpus  = [item.get("code_before_change", "") or "" for item in GLOBAL_KNOWLEDGE_DATA]

    RETRIEVER_PURPOSE,      _ACTIVE_FIELDS["purpose"]     = _build_retriever(purpose_corpus)
    RETRIEVER_FUNCTION,     _ACTIVE_FIELDS["function"]    = _build_retriever(function_corpus)
    RETRIEVER_CODE_BEFORE,  _ACTIVE_FIELDS["code_before"] = _build_retriever(code_before_corpus)


# ─── Stage 1: Rank Sum ───────────────────────────────────────────────────────────
def _compute_rank_sum(
    query_purpose:          Optional[str],
    query_function_summary: Optional[str],
    query_full_code:        Optional[str],
) -> List[int]:
    """
    활성화된 각 필드에 대해 BM25 검색을 수행하고
    item별 rank sum 배열을 반환한다 (값이 낮을수록 관련성 높음).

    쿼리 인자            ↔  코퍼스 인덱스
    query_purpose        ↔  RETRIEVER_PURPOSE      (knowledge.purpose)
    query_function_summary ↔ RETRIEVER_FUNCTION    (knowledge.function)
    query_full_code      ↔  RETRIEVER_CODE_BEFORE  (knowledge.code_before_change)
    """
    n = len(GLOBAL_KNOWLEDGE_DATA)
    rank_sum = [0] * n

    field_queries = [
        ("purpose",     query_purpose,          RETRIEVER_PURPOSE),
        ("function",    query_function_summary,  RETRIEVER_FUNCTION),
        ("code_before", query_full_code,         RETRIEVER_CODE_BEFORE),
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
    query_purpose:          Optional[str],
    query_function_summary: Optional[str],
    query_full_code:        Optional[str],
    top_k: int,
) -> List[RetrievedKnowledgeDTO]:
    """
    Stage 1: rank sum으로 전체 item 정렬
    Stage 2: CVE_id별로 rank sum이 가장 낮은 item 1개 선택 (best representative)
             → 상위 top_k CVE를 RetrievedKnowledgeDTO 리스트로 반환
    """
    rank_sum = _compute_rank_sum(query_purpose, query_function_summary, query_full_code)

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
        # vulnerability_behavior는 중첩 객체 우선, 없으면 flat 필드에서 fallback
        vb = item.get("vulnerability_behavior", {})
        dto = RetrievedKnowledgeDTO(
            cve_id=item.get("CVE_id", ""),
            vulnerability_behavior=VulnerabilityBehaviorDTO(
                vulnerability_cause_description=vb.get("vulnerability_cause_description")
                    or item.get("vulnerability_cause_description", ""),
                trigger_condition=vb.get("trigger_condition")
                    or item.get("trigger_condition", ""),
                specific_code_behavior_causing_vulnerability=vb.get("specific_code_behavior_causing_vulnerability")
                    or item.get("specific_code_behavior_causing_vulnerability", ""),
            ),
            solution_behavior=item.get("solution", ""),
        )
        results.append(dto)

    return results


# ─── main ────────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()

    _ROOT = Path(__file__).resolve().parents[3]   # NLD/
    knowledge_path = str(_ROOT / args.knowledge_file_name)
    input_path     = str(_ROOT / args.input_file_name)
    output_path    = str(_ROOT / args.output_file_name)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    init_retriever(knowledge_path)

    with open(input_path, "r", encoding="utf-8") as f:
        test_data = json.load(f)

    # 출력: RetrievedKnowledgeDTO 리스트를 그대로 직렬화
    out: List[dict] = []
    for item in test_data:
        # diff_retriever.json 항목에서 3개 쿼리 필드 추출
        query_purpose          = item.get("purpose")
        query_function_summary = item.get("function_summary")
        query_full_code        = item.get("full_code")

        retrieved = retrieve_top_k(
            query_purpose          = query_purpose,
            query_function_summary = query_function_summary,
            query_full_code        = query_full_code,
            top_k                  = args.retrieval_top_k,
        )

        # RetrievedKnowledgeDTO.model_dump() → retriever_output_dto 필드 그대로 직렬화
        out.extend([r.model_dump() for r in retrieved])

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=4, ensure_ascii=False)


if __name__ == "__main__":
    main()
