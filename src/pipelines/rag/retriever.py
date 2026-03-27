"""
Hybrid Retriever + GPT Top2 Selector
====================================
Stage 1:
- purpose           ↔ DenseRetriever (LangChain OpenAIEmbeddings)
- function_summary  ↔ DenseRetriever (LangChain OpenAIEmbeddings)
- full_code         ↔ BM25Retriever(code_before_change)
- RRF로 세 결과를 결합하여 top 20 후보 검색

Stage 2:
- top 20 후보를 ChatOpenAI(gpt-4o-mini)에 전달
- 가장 가능성 높은 취약점 2개 선정

입력:
- diff_retriever.json

출력:
- retriever_output_top2.json (하나의 merged json 파일)
"""

import json
import os
import sys
import argparse
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from ...utils.bm25_retriever import BM25Retriever
    from ...utils.dense_retriever import DenseRetriever
    from ...utils.embedding_cache import EmbeddingCache
    from langchain_openai import OpenAIEmbeddings, ChatOpenAI
except ImportError:
    _ROOT = Path(__file__).resolve().parents[3]
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))
    from src.utils.bm25_retriever import BM25Retriever
    from src.utils.dense_retriever import DenseRetriever
    from src.utils.embedding_cache import EmbeddingCache
    from langchain_openai import OpenAIEmbeddings, ChatOpenAI


# ─────────────────────────────────────────────────────────────
# Global state
# ─────────────────────────────────────────────────────────────
GLOBAL_KNOWLEDGE_DATA: Optional[List[dict]] = None

RETRIEVER_PURPOSE: Optional[DenseRetriever] = None
RETRIEVER_FUNCTION: Optional[DenseRetriever] = None
RETRIEVER_CODE_BEFORE: Optional[BM25Retriever] = None

EMBEDDINGS_MODEL: Optional[OpenAIEmbeddings] = None
CHAT_MODEL: Optional[ChatOpenAI] = None

_ACTIVE_FIELDS: Dict[str, bool] = {
    "purpose": False,
    "function": False,
    "code_before": False,
}


# ─────────────────────────────────────────────────────────────
# Utils
# ─────────────────────────────────────────────────────────────
def log(msg: str):
    print(msg, flush=True)


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--diff-path", type=str, required=True, help="Input diff JSON file")
    p.add_argument("--knowledge-dir", type=str, required=True, help="Directory containing knowledge JSON files")
    p.add_argument(
        "--output-path",
        type=str,
        default="data/retriever_output_top2.json",
        help="Path to save merged results"
    )
    p.add_argument("--candidate-k", type=int, default=20, help="Number of retrieval candidates before GPT selection")
    p.add_argument("--final-k", type=int, default=2, help="Number of final vulnerability types selected by GPT")
    p.add_argument("--workers", type=int, default=8, help="Number of parallel workers")
    p.add_argument("--limit", type=int, default=0, help="앞에서부터 N개 item만 처리 (0이면 전체)")
    return p.parse_args()


# ─────────────────────────────────────────────────────────────
# Embedding cache helpers
# ─────────────────────────────────────────────────────────────
def _get_embeddings_with_cache(
    texts: List[str],
    cache: EmbeddingCache,
    embeddings_model: OpenAIEmbeddings
) -> List[List[float]]:
    results: List[Optional[List[float]]] = [None] * len(texts)
    to_fetch_indices: List[int] = []
    to_fetch_texts: List[str] = []
    

    for i, text in enumerate(texts):
        cached = cache.get(text)
        if cached:
            results[i] = cached
        else:
            to_fetch_indices.append(i)
            to_fetch_texts.append(text)

    if to_fetch_texts:
        log(f"[EMB] fetching {len(to_fetch_texts)} new embeddings")
        chunk_size = 100
        total_chunks = (len(to_fetch_texts) - 1) // chunk_size + 1

        for start in range(0, len(to_fetch_texts), chunk_size):
            chunk = to_fetch_texts[start:start + chunk_size]
            chunk_indices = to_fetch_indices[start:start + chunk_size]
            log(f"[EMB]   chunk {start // chunk_size + 1}/{total_chunks}")

            embeddings = embeddings_model.embed_documents(chunk)
            for idx, emb in zip(chunk_indices, embeddings):
                results[idx] = emb
                cache.set(texts[idx], emb)

        log("[EMB] saving cache")
        cache.save_cache()

    return results  # type: ignore


# ─────────────────────────────────────────────────────────────
# Retriever builders
# ─────────────────────────────────────────────────────────────
def _build_bm25_retriever(corpus: List[str], name: str) -> Tuple[BM25Retriever, bool]:
    log(f"[BUILD:BM25:{name}] corpus size = {len(corpus)}")
    is_active = any(text.strip() for text in corpus)
    log(f"[BUILD:BM25:{name}] active = {is_active}")

    retriever = BM25Retriever()
    retriever.set_corpus(corpus)
    return retriever, is_active


def _build_dense_retriever(
    corpus: List[str],
    name: str,
    cache: EmbeddingCache,
    embeddings_model: OpenAIEmbeddings
) -> Tuple[DenseRetriever, bool]:
    log(f"[BUILD:DENSE:{name}] corpus size = {len(corpus)}")
    is_active = any(text.strip() for text in corpus)
    log(f"[BUILD:DENSE:{name}] active = {is_active}")

    if not is_active:
        return DenseRetriever(), False

    embeddings = _get_embeddings_with_cache(corpus, cache, embeddings_model)
    retriever = DenseRetriever()
    retriever.set_corpus(embeddings, corpus)
    return retriever, True


# ─────────────────────────────────────────────────────────────
# Initialization
# ─────────────────────────────────────────────────────────────
def init_retriever(knowledge_dir: str):
    global GLOBAL_KNOWLEDGE_DATA
    global RETRIEVER_PURPOSE, RETRIEVER_FUNCTION, RETRIEVER_CODE_BEFORE
    global EMBEDDINGS_MODEL, CHAT_MODEL, _ACTIVE_FIELDS

    log("[INIT] init_retriever entered")

    EMBEDDINGS_MODEL = OpenAIEmbeddings(
        model="text-embedding-3-small"
    )
    CHAT_MODEL = ChatOpenAI(
        model="gpt-4o-mini",
        temperature=0
    )

    _ROOT = Path(__file__).resolve().parents[3]
    cache_dir = _ROOT / "data" / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    embedding_cache = EmbeddingCache(str(cache_dir / "embeddings.json"))

    GLOBAL_KNOWLEDGE_DATA = []
    knowledge_dir_path = Path(knowledge_dir)

    if not knowledge_dir_path.exists():
        raise FileNotFoundError(f"knowledge_dir does not exist: {knowledge_dir_path}")

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

    purpose_corpus = [safe_text(item.get("purpose")) for item in GLOBAL_KNOWLEDGE_DATA]
    function_corpus = [
        safe_text(item.get("function") or item.get("function_summary"))
        for item in GLOBAL_KNOWLEDGE_DATA
    ]
    code_before_corpus = [
        safe_text(item.get("code_before_change") or item.get("code"))
        for item in GLOBAL_KNOWLEDGE_DATA
    ]

    log("[INIT] building PURPOSE dense retriever")
    RETRIEVER_PURPOSE, _ACTIVE_FIELDS["purpose"] = _build_dense_retriever(
        purpose_corpus, "purpose", embedding_cache, EMBEDDINGS_MODEL
    )

    log("[INIT] building FUNCTION dense retriever")
    RETRIEVER_FUNCTION, _ACTIVE_FIELDS["function"] = _build_dense_retriever(
        function_corpus, "function", embedding_cache, EMBEDDINGS_MODEL
    )

    log("[INIT] building CODE_BEFORE bm25 retriever")
    RETRIEVER_CODE_BEFORE, _ACTIVE_FIELDS["code_before"] = _build_bm25_retriever(
        code_before_corpus, "code_before"
    )

    log("[INIT] init_retriever done")


# ─────────────────────────────────────────────────────────────
# Stage 1: RRF
# ─────────────────────────────────────────────────────────────
def _compute_rrf_scores(
    query_purpose: Optional[str],
    query_function_summary: Optional[str],
    query_full_code: Optional[str],
    k: int = 60,
) -> List[float]:
    if GLOBAL_KNOWLEDGE_DATA is None:
        raise ValueError("GLOBAL_KNOWLEDGE_DATA is not initialized.")

    n = len(GLOBAL_KNOWLEDGE_DATA)
    rrf_scores = [0.0] * n

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
            if EMBEDDINGS_MODEL is None:
                raise ValueError("EMBEDDINGS_MODEL is not initialized.")
            query_emb = EMBEDDINGS_MODEL.embed_query(query_text)
            sorted_idxs = retriever.search(query_emb, top_n=-1)  # type: ignore
        else:
            sorted_idxs = retriever.search(query_text, top_n=-1)  # type: ignore

        log(f"[RANK] search done field={field_name}, returned={len(sorted_idxs)}")

        for rank, idx in enumerate(sorted_idxs, start=1):
            rrf_scores[idx] += 1.0 / (k + rank)

    return rrf_scores


def retrieve_top_k_candidates(
    query_purpose: Optional[str],
    query_function_summary: Optional[str],
    query_full_code: Optional[str],
    top_k: int,
) -> List[dict]:
    """
    Stage 1:
    - 전체 knowledge item에 대해 RRF 점수 계산
    - CVE_id별 최고 점수 item 1개만 유지
    - 상위 top_k개 후보 반환
    """
    if GLOBAL_KNOWLEDGE_DATA is None:
        raise ValueError("GLOBAL_KNOWLEDGE_DATA is not initialized.")

    rrf_scores = _compute_rrf_scores(
        query_purpose=query_purpose,
        query_function_summary=query_function_summary,
        query_full_code=query_full_code,
    )

    sorted_indices = sorted(
        range(len(GLOBAL_KNOWLEDGE_DATA)),
        key=lambda i: rrf_scores[i],
        reverse=True
    )

    seen_cves: Dict[str, Tuple[int, float]] = {}
    for idx in sorted_indices:
        item = GLOBAL_KNOWLEDGE_DATA[idx]
        cve_id = safe_text(item.get("CVE_id") or item.get("cve_id") or f"NO_CVE_{idx}")
        if cve_id not in seen_cves:
            seen_cves[cve_id] = (idx, rrf_scores[idx])

    top_cves = sorted(seen_cves.values(), key=lambda x: x[1], reverse=True)[:top_k]

    results: List[dict] = []
    for item_idx, score in top_cves:
        item = GLOBAL_KNOWLEDGE_DATA[item_idx]
        vb = item.get("vulnerability_behavior", {}) or {}

        results.append({
            "cve_id": safe_text(item.get("CVE_id") or item.get("cve_id")),
            "rrf_score": score,
            "purpose": safe_text(item.get("purpose")),
            "function": safe_text(item.get("function") or item.get("function_summary")),
            "vulnerability_cause_description": safe_text(
                vb.get("vulnerability_cause_description")
                or item.get("vulnerability_cause_description")
            ),
            "trigger_condition": safe_text(
                vb.get("trigger_condition")
                or item.get("trigger_condition")
            ),
            "specific_code_behavior_causing_vulnerability": safe_text(
                vb.get("specific_code_behavior_causing_vulnerability")
                or item.get("specific_code_behavior_causing_vulnerability")
            ),
            "solution_behavior": safe_text(
                item.get("solution_behavior") or item.get("solution")
            ),
        })

    return results


# ─────────────────────────────────────────────────────────────
# Stage 2: GPT selects top 2
# ─────────────────────────────────────────────────────────────
def _build_candidate_summary(candidates: List[dict]) -> str:
    lines: List[str] = []
    for i, item in enumerate(candidates, start=1):
        lines.append(
            f"""[{i}]
CVE_ID: {item.get("cve_id", "")}
RRF_SCORE: {item.get("rrf_score", 0.0):.6f}
PURPOSE: {item.get("purpose", "")}
FUNCTION: {item.get("function", "")}
CAUSE: {item.get("vulnerability_cause_description", "")}
TRIGGER: {item.get("trigger_condition", "")}
CODE_BEHAVIOR: {item.get("specific_code_behavior_causing_vulnerability", "")}
SOLUTION: {item.get("solution_behavior", "")}
""".strip()
        )
    return "\n\n".join(lines)


def select_top_vulnerabilities_with_gpt(
    query_purpose: str,
    query_function_summary: str,
    query_full_code: str,
    candidates: List[dict],
    final_k: int = 2,
) -> List[dict]:
    if CHAT_MODEL is None:
        raise ValueError("CHAT_MODEL is not initialized.")

    candidate_text = _build_candidate_summary(candidates)

    system_prompt = (
        "You are a security analysis assistant.\n"
        "Your job is to read retrieved vulnerability candidates and identify the most likely vulnerability TYPES.\n"
        "Return ONLY valid JSON.\n"
        "Do not include markdown fences.\n"
    )

    user_prompt = f"""
Given the query information and the retrieved candidates, choose the {final_k} most likely vulnerability types.

[Query]
PURPOSE: {query_purpose}
FUNCTION_SUMMARY: {query_function_summary}
FULL_CODE:
{query_full_code}

[Retrieved Candidates]
{candidate_text}

Return JSON in this exact schema:
{{
  "top_vulnerabilities": [
    {{
      "name": "vulnerability type name",
      "reason": "why this type is likely based on repeated evidence from the candidates",
      "supporting_cve_ids": ["CVE-...","CVE-..."]
    }}
  ]
}}

Rules:
- Return exactly {final_k} items.
- Focus on vulnerability TYPES, not specific CVEs.
- Use concise names like "Buffer Overflow", "Use-After-Free", "Null Pointer Dereference", "Integer Overflow".
- supporting_cve_ids should contain the most relevant candidate CVE IDs.
- Return JSON only.
""".strip()

    response = CHAT_MODEL.invoke([
        ("system", system_prompt),
        ("human", user_prompt),
    ])

    content = response.content if hasattr(response, "content") else str(response)
    content = content.strip()

    try:
        parsed = json.loads(content)
        top_vulns = parsed.get("top_vulnerabilities", [])
        if not isinstance(top_vulns, list):
            raise ValueError("top_vulnerabilities is not a list")

        cleaned = []
        for item in top_vulns[:final_k]:
            cleaned.append({
                "name": safe_text(item.get("name")),
                "reason": safe_text(item.get("reason")),
                "supporting_cve_ids": item.get("supporting_cve_ids", []),
            })

        while len(cleaned) < final_k:
            cleaned.append({
                "name": "",
                "reason": "GPT output parsing fallback",
                "supporting_cve_ids": [],
            })

        return cleaned

    except Exception as e:
        log(f"[GPT] parse failed: {e}")
        fallback = []
        for item in candidates[:final_k]:
            fallback.append({
                "name": item.get("vulnerability_cause_description", "")[:80],
                "reason": "Fallback due to GPT JSON parse failure",
                "supporting_cve_ids": [item.get("cve_id", "")] if item.get("cve_id") else [],
            })
        return fallback


# ─────────────────────────────────────────────────────────────
# Per-item processing
# ─────────────────────────────────────────────────────────────
def process_function(item: dict, args) -> Optional[dict]:
    item_id = item.get("id")
    if item_id is None:
        log("[ITEM] skipped item without id")
        return None

    log(f"[ITEM {item_id:04d}] start")

    query_purpose = safe_text(item.get("purpose"))
    query_function_summary = safe_text(item.get("function_summary") or item.get("function"))
    query_full_code = safe_text(item.get("full_code") or item.get("code"))

    candidates = retrieve_top_k_candidates(
        query_purpose=query_purpose,
        query_function_summary=query_function_summary,
        query_full_code=query_full_code,
        top_k=args.candidate_k,
    )
    log(f"[ITEM {item_id:04d}] candidate count = {len(candidates)}")

    top_vulnerabilities = select_top_vulnerabilities_with_gpt(
        query_purpose=query_purpose,
        query_function_summary=query_function_summary,
        query_full_code=query_full_code,
        candidates=candidates,
        final_k=args.final_k,
    )
    log(f"[ITEM {item_id:04d}] final top vulnerabilities = {len(top_vulnerabilities)}")

    return {
        "id": item_id,
        "full_code": query_full_code,
        "top_vulnerabilities": top_vulnerabilities,
    }


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────
def main():
    args = parse_args()
    log("[MAIN] script start")

    _ROOT = Path(__file__).resolve().parents[3]
    log(f"[MAIN] root = {_ROOT}")

    knowledge_dir = str(_ROOT / args.knowledge_dir) if not Path(args.knowledge_dir).is_absolute() else args.knowledge_dir
    input_path = str(_ROOT / args.diff_path) if not Path(args.diff_path).is_absolute() else args.diff_path
    output_path = str(_ROOT / args.output_path) if not Path(args.output_path).is_absolute() else args.output_path

    log(f"[MAIN] input_path = {input_path}")
    log(f"[MAIN] knowledge_dir = {knowledge_dir}")
    log(f"[MAIN] output_path = {output_path}")
    log(f"[MAIN] candidate_k = {args.candidate_k}, final_k = {args.final_k}, workers = {args.workers}, limit = {args.limit}")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

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
            executor.submit(process_function, item, args): item
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

    out.sort(key=lambda x: x["id"])

    log(f"[MAIN] writing merged output count = {len(out)}")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=4, ensure_ascii=False)

    log("[MAIN] done")


if __name__ == "__main__":
    main()