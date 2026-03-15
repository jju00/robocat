"""
2-Stage Retriever
=================
Stage 1: knowledge의 3개 코퍼스 필드에 대해 각각 BM25 검색 후 rank sum으로 전체 item 랭킹 계산
         쿼리 (diff_retriever.json)         ↔  코퍼스 (knowledge)
         ──────────────────────────────────────────────────────
         full_code        (원본 함수 전체코드) ↔  code_before_change
         purpose          (함수 목적 요약)     ↔  purpose
         function_summary (함수 동작 요약)    ↔  function

Stage 2: CVE 단위로 rank sum 최소 item 1개만 선택 → top-k CVE 반환

입력 쿼리: diff_retriever.json 항목의 full_code / purpose / function_summary
출력:      List[RetrieverResultDTO]
"""

import json
import os
import sys
import argparse
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# 패키지 내 import (python -m) / 직접 실행 (python src/...) 양쪽 지원
try:
    from ...utils.bm25_retriever import BM25Retriever
    from ...dto.retriever_output_dto import (
        RetrievedKnowledgeDTO,
        VulnerabilityBehaviorDTO,
        RetrieverResultDTO,
    )
except ImportError:
    _ROOT = Path(__file__).resolve().parents[3]   # NLD/
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))
    from src.utils.bm25_retriever import BM25Retriever
    from src.dto.retriever_output_dto import (
        RetrievedKnowledgeDTO,
        VulnerabilityBehaviorDTO,
        RetrieverResultDTO,
    )

# ─── 전역 캐시 ──────────────────────────────────────────────────────────────
GLOBAL_KNOWLEDGE_DATA: Optional[List[dict]] = None

RETRIEVER_PURPOSE: Optional[BM25Retriever] = None
RETRIEVER_FUNCTION: Optional[BM25Retriever] = None
RETRIEVER_CODE_BEFORE: Optional[BM25Retriever] = None

_ACTIVE_FIELDS: Dict[str, bool] = {
    "purpose": False,
    "function": False,
    "code_before": False,
}


# ─── 로그 헬퍼 ───────────────────────────────────────────────────────────────
def log(msg: str):
    print(msg, flush=True)


# ─── CLI ────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--diff-path", type=str, required=True, help="Input diff JSON file")
    p.add_argument("--knowledge-dir", type=str, required=True, help="Directory containing CWE knowledge files")
    p.add_argument("--cases-dir", type=str, required=True, help="Directory to save per-function results")
    p.add_argument("--output-path", type=str, required=True, help="Path to save merged results")
    p.add_argument("--top-k", type=int, default=20, help="Number of retrieved knowledge items")
    p.add_argument("--workers", type=int, default=8, help="Number of parallel workers")
    p.add_argument("--resume", action="store_true", help="Skip already processed functions")
    p.add_argument("--limit", type=int, default=0, help="테스트용: 앞에서부터 N개 item만 처리 (0이면 전체)")
    return p.parse_args()


# ─── retriever initialization ───────────────────────────────────────────────
def _build_retriever(corpus: List[str], name: str) -> Tuple[BM25Retriever, bool]:
    """
    코퍼스로 BM25Retriever를 빌드하고, 유효 항목이 있는지 여부를 함께 반환.
    """
    log(f"[BUILD:{name}] corpus size = {len(corpus)}")
    is_active = any(text.strip() for text in corpus)
    log(f"[BUILD:{name}] active = {is_active}")

    retriever = BM25Retriever()
    log(f"[BUILD:{name}] BM25Retriever created")

    retriever.set_corpus(corpus)
    log(f"[BUILD:{name}] set_corpus done")

    return retriever, is_active


def init_retriever(knowledge_dir: str):
    """
    knowledge JSON 파일들을 로드하고 3개의 BM25 인덱스를 생성한다.
    """
    global GLOBAL_KNOWLEDGE_DATA
    global RETRIEVER_PURPOSE, RETRIEVER_FUNCTION, RETRIEVER_CODE_BEFORE
    global _ACTIVE_FIELDS

    log("[INIT] init_retriever entered")

    GLOBAL_KNOWLEDGE_DATA = []
    knowledge_dir_path = Path(knowledge_dir)

    if not knowledge_dir_path.exists():
        raise FileNotFoundError(f"knowledge_dir does not exist: {knowledge_dir_path}")
    if not knowledge_dir_path.is_dir():
        raise NotADirectoryError(f"knowledge_dir is not a directory: {knowledge_dir_path}")

    json_files = sorted(knowledge_dir_path.glob("*.json"))
    log(f"[INIT] knowledge files found = {len(json_files)}")

    for idx, json_file in enumerate(json_files, start=1):
        log(f"[INIT] loading ({idx}/{len(json_files)}): {json_file.name}")
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, list):
            GLOBAL_KNOWLEDGE_DATA.extend(data)
        elif isinstance(data, dict):
            GLOBAL_KNOWLEDGE_DATA.append(data)

    log(f"[INIT] total knowledge items = {len(GLOBAL_KNOWLEDGE_DATA)}")

    purpose_corpus = [item.get("purpose", "") or "" for item in GLOBAL_KNOWLEDGE_DATA]
    function_corpus = [item.get("function", "") or "" for item in GLOBAL_KNOWLEDGE_DATA]
    code_before_corpus = [item.get("code_before_change", "") or "" for item in GLOBAL_KNOWLEDGE_DATA]

    log("[INIT] building PURPOSE retriever")
    RETRIEVER_PURPOSE, _ACTIVE_FIELDS["purpose"] = _build_retriever(purpose_corpus, "purpose")

    log("[INIT] building FUNCTION retriever")
    RETRIEVER_FUNCTION, _ACTIVE_FIELDS["function"] = _build_retriever(function_corpus, "function")

    log("[INIT] building CODE_BEFORE retriever")
    RETRIEVER_CODE_BEFORE, _ACTIVE_FIELDS["code_before"] = _build_retriever(code_before_corpus, "code_before")

    log("[INIT] init_retriever done")


# ─── Stage 1: Rank Sum ──────────────────────────────────────────────────────
def _compute_rank_sum(
    query_purpose: Optional[str],
    query_function_summary: Optional[str],
    query_full_code: Optional[str],
) -> List[int]:
    """
    활성화된 각 필드에 대해 BM25 검색을 수행하고
    item별 rank sum 배열을 반환한다 (값이 낮을수록 관련성 높음).
    """
    n = len(GLOBAL_KNOWLEDGE_DATA)
    rank_sum = [0] * n

    field_queries = [
        ("purpose", query_purpose, RETRIEVER_PURPOSE),
        ("function", query_function_summary, RETRIEVER_FUNCTION),
        ("code_before", query_full_code, RETRIEVER_CODE_BEFORE),
    ]

    for field_name, query_text, retriever in field_queries:
        if not _ACTIVE_FIELDS[field_name]:
            log(f"[RANK] skip inactive field: {field_name}")
            continue
        if not query_text or not query_text.strip():
            log(f"[RANK] skip empty query field: {field_name}")
            continue

        log(f"[RANK] searching field={field_name}")
        sorted_idxs = retriever.search(query_text, top_n=-1)
        log(f"[RANK] search done field={field_name}, returned={len(sorted_idxs)}")

        for rank, idx in enumerate(sorted_idxs):
            rank_sum[idx] += rank + 1

    return rank_sum


# ─── Stage 2: CVE별 best item 선택 → top-k ────────────────────────────────
def retrieve_top_k(
    query_purpose: Optional[str],
    query_function_summary: Optional[str],
    query_full_code: Optional[str],
    top_k: int,
) -> List[RetrievedKnowledgeDTO]:
    """
    Stage 1: rank sum으로 전체 item 정렬
    Stage 2: CVE_id별로 rank sum이 가장 낮은 item 1개 선택 (best representative)
             → 상위 top_k CVE를 RetrievedKnowledgeDTO 리스트로 반환
    """
    rank_sum = _compute_rank_sum(query_purpose, query_function_summary, query_full_code)

    sorted_indices = sorted(range(len(GLOBAL_KNOWLEDGE_DATA)), key=lambda i: rank_sum[i])

    seen_cves: Dict[str, Tuple[int, int]] = {}
    for idx in sorted_indices:
        cve_id = GLOBAL_KNOWLEDGE_DATA[idx].get("CVE_id")
        if cve_id and cve_id not in seen_cves:
            seen_cves[cve_id] = (idx, rank_sum[idx])

    top_cves = sorted(seen_cves.values(), key=lambda t: t[1])[:top_k]

    results: List[RetrievedKnowledgeDTO] = []
    for item_idx, _ in top_cves:
        item = GLOBAL_KNOWLEDGE_DATA[item_idx]
        vb = item.get("vulnerability_behavior", {})

        dto = RetrievedKnowledgeDTO(
            cve_id=item.get("CVE_id", ""),
            vulnerability_behavior=VulnerabilityBehaviorDTO(
                vulnerability_cause_description=vb.get("vulnerability_cause_description")
                or item.get("vulnerability_cause_description", ""),
                trigger_condition=vb.get("trigger_condition")
                or item.get("trigger_condition", ""),
                specific_code_behavior_causing_vulnerability=vb.get(
                    "specific_code_behavior_causing_vulnerability"
                )
                or item.get("specific_code_behavior_causing_vulnerability", ""),
            ),
            solution_behavior=item.get("solution", "") or item.get("solution_behavior", ""),
        )
        results.append(dto)

    return results


def process_function(item: dict, args, cases_dir: Path) -> Optional[dict]:
    item_id = item.get("id")
    if item_id is None:
        log("[ITEM] skipped item without id")
        return None

    log(f"[ITEM {item_id:04d}] start")

    case_path = cases_dir / f"{item_id:04d}.json"
    if args.resume and case_path.exists():
        log(f"[ITEM {item_id:04d}] resume hit -> load existing")
        with open(case_path, "r", encoding="utf-8") as f:
            return json.load(f)

    query_purpose = item.get("purpose")
    query_function_summary = item.get("function_summary")
    query_full_code = item.get("full_code")

    retrieved = retrieve_top_k(
        query_purpose=query_purpose,
        query_function_summary=query_function_summary,
        query_full_code=query_full_code,
        top_k=args.top_k,
    )
    log(f"[ITEM {item_id:04d}] retrieved count = {len(retrieved)}")

    result_dto = RetrieverResultDTO(
        id=item_id,
        full_code=query_full_code or "",
        retrieved_knowledge=retrieved,
    )
    result_dict = result_dto.model_dump()

    with open(case_path, "w", encoding="utf-8") as f:
        json.dump(result_dict, f, indent=4, ensure_ascii=False)

    log(f"[ITEM {item_id:04d}] saved -> {case_path}")
    return result_dict


# ─── main ───────────────────────────────────────────────────────────────────
def main():
    args = parse_args()
    log("[MAIN] script start")

    _ROOT = Path(__file__).resolve().parents[3]
    log(f"[MAIN] root = {_ROOT}")

    knowledge_dir = str(_ROOT / args.knowledge_dir) if not Path(args.knowledge_dir).is_absolute() else args.knowledge_dir
    input_path = str(_ROOT / args.diff_path) if not Path(args.diff_path).is_absolute() else args.diff_path
    output_path = str(_ROOT / args.output_path) if not Path(args.output_path).is_absolute() else args.output_path
    cases_dir_path = _ROOT / args.cases_dir if not Path(args.cases_dir).is_absolute() else Path(args.cases_dir)

    log(f"[MAIN] input_path = {input_path}")
    log(f"[MAIN] knowledge_dir = {knowledge_dir}")
    log(f"[MAIN] cases_dir = {cases_dir_path}")
    log(f"[MAIN] output_path = {output_path}")
    log(f"[MAIN] top_k = {args.top_k}, workers = {args.workers}, resume = {args.resume}, limit = {args.limit}")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    os.makedirs(cases_dir_path, exist_ok=True)

    log("[MAIN] init_retriever start")
    init_retriever(knowledge_dir)
    log("[MAIN] init_retriever finished")

    log("[MAIN] loading diff input")
    with open(input_path, "r", encoding="utf-8") as f:
        test_data = json.load(f)

    log(f"[MAIN] diff items loaded = {len(test_data)}")

    if args.limit and args.limit > 0:
        test_data = test_data[:args.limit]
        log(f"[MAIN] limited diff items = {len(test_data)}")

    out = []

    log("[MAIN] ThreadPoolExecutor start")
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(process_function, item, args, cases_dir_path): item
            for item in test_data
        }
        log(f"[MAIN] futures submitted = {len(futures)}")

        for future in as_completed(futures):
            try:
                res = future.result()
                if res is not None:
                    out.append(res)
                    log(f"[MAIN] collected result count = {len(out)}")
            except Exception as e:
                item = futures[future]
                item_id = item.get("id", "UNKNOWN")
                log(f"[ERROR] item_id={item_id} failed: {e}")

    log("[MAIN] sorting merged output")
    out.sort(key=lambda x: x["id"])

    log(f"[MAIN] writing merged output count = {len(out)}")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=4, ensure_ascii=False)

    log("[MAIN] done")


if __name__ == "__main__":
    main()