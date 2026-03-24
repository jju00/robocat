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
    from ...utils.dense_retriever import DenseRetriever
    from ...utils.llm_client import get_llm_client, OpenAIClient
    from ...utils.embedding_cache import EmbeddingCache
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
    from src.utils.dense_retriever import DenseRetriever
    from src.utils.llm_client import get_llm_client, OpenAIClient
    from src.utils.embedding_cache import EmbeddingCache
    from src.dto.retriever_output_dto import (
        RetrievedKnowledgeDTO,
        VulnerabilityBehaviorDTO,
        RetrieverResultDTO,
    )

# ─── 전역 캐시 ──────────────────────────────────────────────────────────────
GLOBAL_KNOWLEDGE_DATA: Optional[List[dict]] = None

# EMBEDDING_CACHE: Optional[EmbeddingCache] = None
# LLM_CLIENT: Optional[OpenAIClient] = None

RETRIEVER_PURPOSE: Optional[DenseRetriever] = None
RETRIEVER_FUNCTION: Optional[DenseRetriever] = None
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
# ─── Embedding Helper ────────────────────────────────────────────────────────
def _get_embeddings_with_cache(texts: List[str], cache: EmbeddingCache, client: OpenAIClient) -> List[List[float]]:
    """
    텍스트 리스트에 대해 캐시를 확인하고 대량으로 임베딩을 생성한다.
    """
    results = [None] * len(texts)
    to_fetch_indices = []
    to_fetch_texts = []

    for i, text in enumerate(texts):
        cached = cache.get(text)
        if cached:
            results[i] = cached
        else:
            to_fetch_indices.append(i)
            to_fetch_texts.append(text)

    if to_fetch_texts:
        log(f"[EMB] fetching {len(to_fetch_texts)} new embeddings from OpenAI")
        # OpenAI API limit: 보통 한 번에 2048개 정도까지 가능하지만 안전하게 100개씩 처리
        chunk_size = 100
        for i in range(0, len(to_fetch_texts), chunk_size):
            chunk = to_fetch_texts[i : i + chunk_size]
            chunk_indices = to_fetch_indices[i : i + chunk_size]
            log(f"[EMB]   chunk {i//chunk_size + 1}/{(len(to_fetch_texts)-1)//chunk_size + 1}")
            embeddings = client.generate_embeddings(chunk)
            for idx, emb in zip(chunk_indices, embeddings):
                results[idx] = emb
                cache.set(texts[idx], emb)
        
        log("[EMB] saving cache")
        cache.save_cache()

    return results  # type: ignore


# ─── retriever initialization ───────────────────────────────────────────────
def _build_bm25_retriever(corpus: List[str], name: str) -> Tuple[BM25Retriever, bool]:
    log(f"[BUILD:BM25:{name}] corpus size = {len(corpus)}")
    is_active = any(text.strip() for text in corpus)
    log(f"[BUILD:BM25:{name}] active = {is_active}")
    retriever = BM25Retriever()
    retriever.set_corpus(corpus)
    return retriever, is_active


def _build_dense_retriever(corpus: List[str], name: str, cache: EmbeddingCache, client: OpenAIClient) -> Tuple[DenseRetriever, bool]:
    log(f"[BUILD:DENSE:{name}] corpus size = {len(corpus)}")
    is_active = any(text.strip() for text in corpus)
    log(f"[BUILD:DENSE:{name}] active = {is_active}")
    
    if not is_active:
        return DenseRetriever(), False

    embeddings = _get_embeddings_with_cache(corpus, cache, client)
    retriever = DenseRetriever()
    retriever.set_corpus(embeddings, corpus)
    return retriever, True


def init_retriever(knowledge_dir: str):
    """
    knowledge JSON 파일들을 로드하고 Hybrid(Dense + BM25) 인덱스를 생성한다.
    """
    global GLOBAL_KNOWLEDGE_DATA
    global RETRIEVER_PURPOSE, RETRIEVER_FUNCTION, RETRIEVER_CODE_BEFORE
    global _ACTIVE_FIELDS
    # global LLM_CLIENT, EMBEDDING_CACHE

    log("[INIT] init_retriever entered")

    # Utilities initialization
    llm_client = get_llm_client("gpt-4o-mini")
    if not isinstance(llm_client, OpenAIClient):
        raise ValueError("OpenAIClient is required for Dense retrieval")
    
    _ROOT = Path(__file__).resolve().parents[3]
    cache_dir = _ROOT / "data" / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    embedding_cache = EmbeddingCache(str(cache_dir / "embeddings.json"))

    GLOBAL_KNOWLEDGE_DATA = []
    knowledge_dir_path = Path(knowledge_dir)

    if not knowledge_dir_path.exists():
        raise FileNotFoundError(f"knowledge_dir does not exist: {knowledge_dir_path}")

    # CWE 하위 디렉토리까지 모두 탐색
    json_files = sorted(knowledge_dir_path.rglob("*.json"))
    log(f"[INIT] knowledge files found = {len(json_files)}")

    for idx, json_file in enumerate(json_files, start=1):
        if idx % 10 == 0 or idx == len(json_files):
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

    log("[INIT] building PURPOSE dense retriever")
    RETRIEVER_PURPOSE, _ACTIVE_FIELDS["purpose"] = _build_dense_retriever(purpose_corpus, "purpose", embedding_cache, llm_client)

    log("[INIT] building FUNCTION dense retriever")
    RETRIEVER_FUNCTION, _ACTIVE_FIELDS["function"] = _build_dense_retriever(function_corpus, "function", embedding_cache, llm_client)

    log("[INIT] building CODE_BEFORE bm25 retriever")
    RETRIEVER_CODE_BEFORE, _ACTIVE_FIELDS["code_before"] = _build_bm25_retriever(code_before_corpus, "code_before")

    log("[INIT] init_retriever done")


# ─── Stage 1: RRF (Reciprocal Rank Fusion) ──────────────────────────────────
def _compute_rrf_scores(
    query_purpose: Optional[str],
    query_function_summary: Optional[str],
    query_full_code: Optional[str],
    k: int = 60,
) -> List[float]:
    """
    각 필드에 대해 검색을 수행하고 RRF (Reciprocal Rank Fusion) 점수를 계산한다.
    점수가 높을수록 관련성이 높음.
    """
    n = len(GLOBAL_KNOWLEDGE_DATA)
    rrf_scores = [0.0] * n

    # Utils for dense query
    llm_client = get_llm_client("gpt-4o-mini")
    if not isinstance(llm_client, OpenAIClient):
        raise ValueError("OpenAIClient is required for Dense retrieval")

    field_configs = [
        ("purpose", query_purpose, RETRIEVER_PURPOSE, "dense"),
        ("function", query_function_summary, RETRIEVER_FUNCTION, "dense"),
        ("code_before", query_full_code, RETRIEVER_CODE_BEFORE, "bm25"),
    ]

    for field_name, query_text, retriever, r_type in field_configs:
        if not _ACTIVE_FIELDS[field_name]:
            continue
        if not query_text or not query_text.strip():
            continue

        log(f"[RANK] searching field={field_name} (type={r_type})")
        
        if r_type == "dense":
            # query_text에 대한 임베딩 생성 (캐시 안 함 - 쿼리는 매번 다를 수 있으므로)
            query_emb = llm_client.generate_embeddings([query_text])[0]
            sorted_idxs = retriever.search(query_emb, top_n=-1) # type: ignore
        else:
            sorted_idxs = retriever.search(query_text, top_n=-1) # type: ignore
            
        log(f"[RANK] search done field={field_name}, returned={len(sorted_idxs)}")

        for rank, idx in enumerate(sorted_idxs):
            # RRF formula: 1 / (k + rank)
            # rank는 0-based이므로 1을 더해줌 (elasticsearch 등과 맞춤)
            rrf_scores[idx] += 1.0 / (k + rank + 1)

    return rrf_scores


# ─── Stage 2: CVE별 best item 선택 → top-k ────────────────────────────────
def retrieve_top_k(
    query_purpose: Optional[str],
    query_function_summary: Optional[str],
    query_full_code: Optional[str],
    top_k: int,
) -> List[RetrievedKnowledgeDTO]:
    """
    Stage 1: RRF 점수로 전체 item 정렬 (높을수록 좋음)
    Stage 2: CVE_id별로 RRF 점수가 가장 높은 item 1개 선택 (best representative)
             → 상위 top_k CVE를 RetrievedKnowledgeDTO 리스트로 반환
    """
    # rrf_scores: 높은 점수가 더 관련성 높음
    rrf_scores = _compute_rrf_scores(query_purpose, query_function_summary, query_full_code)

    # 점수 내림차순 정렬
    sorted_indices = sorted(range(len(GLOBAL_KNOWLEDGE_DATA)), key=lambda i: rrf_scores[i], reverse=True)

    seen_cves: Dict[str, Tuple[int, float]] = {}
    for idx in sorted_indices:
        cve_id = GLOBAL_KNOWLEDGE_DATA[idx].get("CVE_id")
        if cve_id and cve_id not in seen_cves:
            seen_cves[cve_id] = (idx, rrf_scores[idx])

    # CVE 대표 item을 점수 기준 재정렬(내림차순) 후 top-k 선택
    top_cves = sorted(seen_cves.values(), key=lambda t: t[1], reverse=True)[:top_k]

    results: List[RetrievedKnowledgeDTO] = []
    for item_idx, score in top_cves:
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