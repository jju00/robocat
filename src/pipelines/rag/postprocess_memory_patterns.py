from __future__ import annotations

import argparse
import ast
import json
import re
from pathlib import Path
from typing import Any

from langchain_openai import ChatOpenAI

from src.dto.memory_corruption_patterns import (
    MEMORY_CORRUPTION_PATTERNS,
    find_memory_corruption_pattern,
)


# =========================
# 기본 유틸
# =========================
def safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def safe_list_of_str(value: Any, limit: int | None = None) -> list[str]:
    if value is None:
        result: list[str] = []
    elif isinstance(value, list):
        result = [str(x).strip() for x in value if str(x).strip()]
    else:
        text = str(value).strip()
        result = [text] if text else []

    if limit is not None:
        result = result[:limit]
    return result


def normalize_name_for_compare(name: str) -> str:
    text = safe_str(name).strip().lower()
    text = text.replace("_", " ").replace("-", " ")
    text = re.sub(r"\s+", " ", text)
    return text


def dedupe_keep_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        key = normalize_name_for_compare(item)
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(item.strip())
    return result


# =========================
# 기존 결과 enrich
# =========================
def enrich_top_vulnerability(vuln: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    name = safe_str(vuln.get("name")).strip()
    reason = safe_str(vuln.get("reason")).strip()
    supporting_cve_ids = safe_list_of_str(vuln.get("supporting_cve_ids"), limit=3)

    matched = find_memory_corruption_pattern(name)

    enriched: dict[str, Any] = {
        "name": name,
        "reason": reason,
        "supporting_cve_ids": supporting_cve_ids,
        "representative_pattern": None,
        "memory_corruption_category": None,
        "cwe_ids": [],
        "representative_code_examples": [],
        "common_indicators": [],
    }

    if matched:
        enriched["name"] = safe_str(matched.get("name")).strip() or name
        enriched["representative_pattern"] = matched.get("representative_pattern")
        enriched["memory_corruption_category"] = matched.get("category")
        enriched["cwe_ids"] = safe_list_of_str(matched.get("cwe_ids"))
        enriched["representative_code_examples"] = safe_list_of_str(
            matched.get("representative_code_examples")
        )
        enriched["common_indicators"] = safe_list_of_str(matched.get("common_indicators"))
        return enriched, None

    unmatched_name = name if name else None
    return enriched, unmatched_name


# =========================
# 패턴 파일 읽기/쓰기
# =========================
PATTERNS_VAR_NAME = "MEMORY_CORRUPTION_PATTERNS"


def load_patterns_file_text(patterns_path: Path) -> str:
    if not patterns_path.exists():
        raise FileNotFoundError(f"patterns file not found: {patterns_path}")
    return patterns_path.read_text(encoding="utf-8")


def parse_existing_patterns(patterns_path: Path) -> list[dict[str, Any]]:
    text = load_patterns_file_text(patterns_path)

    try:
        module = ast.parse(text, filename=str(patterns_path))
    except SyntaxError as e:
        raise ValueError(f"Failed to parse python file {patterns_path}: {e}") from e

    for node in module.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == PATTERNS_VAR_NAME:
                    try:
                        parsed = ast.literal_eval(node.value)
                    except Exception as e:
                        raise ValueError(
                            f"Failed to literal_eval {PATTERNS_VAR_NAME} from {patterns_path}: {e}"
                        ) from e

                    if not isinstance(parsed, list):
                        raise ValueError(f"{PATTERNS_VAR_NAME} must be a list")
                    return parsed

    raise ValueError(f"Could not find {PATTERNS_VAR_NAME} in {patterns_path}")


def write_patterns_file(patterns_path: Path, patterns: list[dict[str, Any]]) -> None:
    patterns_path.parent.mkdir(parents=True, exist_ok=True)

    content = (
        '"""\n'
        "Memory corruption pattern dictionary.\n"
        "이 파일은 postprocess_memory_patterns.py가 확장/갱신할 수 있다.\n"
        '"""\n\n'
        "from __future__ import annotations\n\n"
        f"{PATTERNS_VAR_NAME} = "
        + json.dumps(patterns, indent=4, ensure_ascii=False)
        + "\n\n\n"
        "def normalize_vulnerability_name(name: str) -> str:\n"
        "    if not name:\n"
        "        return \"\"\n"
        "    text = str(name).strip().lower()\n"
        "    text = text.replace(\"_\", \" \").replace(\"-\", \" \")\n"
        "    import re\n"
        "    text = re.sub(r\"\\s+\", \" \", text)\n"
        "    return text\n\n\n"
        "def find_memory_corruption_pattern(name: str):\n"
        "    if not name:\n"
        "        return None\n\n"
        "    target = normalize_vulnerability_name(name)\n\n"
        f"    for item in {PATTERNS_VAR_NAME}:\n"
        "        names = [item.get(\"name\", \"\"), *item.get(\"aliases\", [])]\n"
        "        normalized = [normalize_vulnerability_name(x) for x in names if x]\n"
        "        if target in normalized:\n"
        "            return item\n\n"
        f"    for item in {PATTERNS_VAR_NAME}:\n"
        "        names = [item.get(\"name\", \"\"), *item.get(\"aliases\", [])]\n"
        "        normalized = [normalize_vulnerability_name(x) for x in names if x]\n"
        "        for candidate in normalized:\n"
        "            if candidate and (candidate in target or target in candidate):\n"
        "                return item\n\n"
        "    return None\n"
    )

    patterns_path.write_text(content, encoding="utf-8")


# =========================
# alias 흡수 vs 새 항목 추가
# =========================
def build_alias_lookup(patterns: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    lookup: dict[str, dict[str, Any]] = {}
    for item in patterns:
        names = [safe_str(item.get("name")), *safe_list_of_str(item.get("aliases"))]
        for name in names:
            norm = normalize_name_for_compare(name)
            if norm:
                lookup[norm] = item
    return lookup


def guess_existing_parent_pattern(
    unmatched_name: str, patterns: list[dict[str, Any]]
) -> dict[str, Any] | None:
    target = normalize_name_for_compare(unmatched_name)

    for item in patterns:
        canonical = normalize_name_for_compare(item.get("name", ""))
        if canonical and canonical in target:
            return item

    heuristics = [
        ("buffer overflow", "Buffer Overflow"),
        ("heap buffer overflow", "Buffer Overflow"),
        ("stack buffer overflow", "Buffer Overflow"),
        ("out of bounds write", "Out-of-Bounds Write"),
        ("oob write", "Out-of-Bounds Write"),
        ("out of bounds read", "Out-of-Bounds Read"),
        ("oob read", "Out-of-Bounds Read"),
        ("use after free", "Use After Free"),
        ("uaf", "Use After Free"),
        ("double free", "Double Free"),
        ("invalid free", "Invalid Free"),
        ("format string", "Format String Bug"),
        ("null pointer", "Null Pointer Dereference"),
        ("integer overflow", "Integer Overflow"),
        ("integer underflow", "Integer Underflow"),
        ("off by one", "Off-by-One Error"),
        ("memory leak", "Memory Leak"),
        ("dangling pointer", "Dangling Pointer"),
    ]

    matched_canonical_name = None
    for key, canonical_name in heuristics:
        if key in target:
            matched_canonical_name = canonical_name
            break

    if not matched_canonical_name:
        return None

    for item in patterns:
        if normalize_name_for_compare(item.get("name", "")) == normalize_name_for_compare(
            matched_canonical_name
        ):
            return item

    return None


# =========================
# LLM 초안 생성
# =========================
def make_llm(model_name: str, temperature: float) -> ChatOpenAI:
    return ChatOpenAI(model=model_name, temperature=temperature)


def build_llm_prompt(unmatched_name: str) -> str:
    return f"""
You are helping expand a Python dictionary for memory corruption vulnerability patterns.

Target vulnerability name:
{unmatched_name}

Return ONLY valid JSON with this schema:
{{
  "canonical_name": "...",
  "aliases": ["...", "..."],
  "representative_pattern": "...",
  "cwe_ids": ["CWE-..."],
  "representative_code_examples": [
    "...",
    "..."
  ],
  "common_indicators": [
    "...",
    "..."
  ]
}}

Rules:
1. This is for memory corruption related vulnerabilities only.
2. representative_pattern must be one concise Korean sentence.
3. common_indicators must be short Korean phrases.
4. representative_code_examples must be SHORT, safe, non-exploit illustrative snippets only.
5. Do not include markdown fences.
6. cwe_ids should be strings like "CWE-120".
7. aliases must include the original meaning in normalized English forms.
8. If the name is a variant of an existing canonical weakness, normalize it to the common canonical name.
""".strip()


def call_llm_json(llm: ChatOpenAI, prompt: str) -> dict[str, Any]:
    response = llm.invoke(prompt)
    text = getattr(response, "content", response)

    if isinstance(text, list):
        text = "".join(
            part.get("text", "") if isinstance(part, dict) else str(part) for part in text
        )

    text = safe_str(text).strip()
    text = re.sub(r"^```json\s*", "", text)
    text = re.sub(r"^```\s*", "", text)
    text = re.sub(r"\s*```$", "", text)

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"LLM JSON parse failed: {e}\nRaw response:\n{text}") from e

    if not isinstance(parsed, dict):
        raise ValueError("LLM response must be a JSON object")

    return parsed


def generate_pattern_with_llm(llm: ChatOpenAI, unmatched_name: str) -> dict[str, Any]:
    prompt = build_llm_prompt(unmatched_name)
    raw = call_llm_json(llm, prompt)

    canonical_name = safe_str(raw.get("canonical_name")).strip() or unmatched_name
    aliases = safe_list_of_str(raw.get("aliases"))
    aliases = dedupe_keep_order([unmatched_name, canonical_name, *aliases])

    representative_pattern = safe_str(raw.get("representative_pattern")).strip()
    cwe_ids = dedupe_keep_order(safe_list_of_str(raw.get("cwe_ids")))
    representative_code_examples = dedupe_keep_order(
        safe_list_of_str(raw.get("representative_code_examples"), limit=3)
    )
    common_indicators = dedupe_keep_order(safe_list_of_str(raw.get("common_indicators"), limit=6))

    return {
        "name": canonical_name,
        "aliases": aliases,
        "category": "memory_corruption",
        "representative_pattern": representative_pattern,
        "cwe_ids": cwe_ids,
        "representative_code_examples": representative_code_examples,
        "common_indicators": common_indicators,
    }


# =========================
# 패턴 자동 확장
# =========================
def merge_or_append_pattern(
    generated: dict[str, Any],
    patterns: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], str]:
    target_name = generated.get("name", "")
    existing = guess_existing_parent_pattern(target_name, patterns)

    if existing:
        merged_aliases = dedupe_keep_order(
            [
                *safe_list_of_str(existing.get("aliases")),
                *safe_list_of_str(generated.get("aliases")),
                safe_str(target_name),
            ]
        )
        existing["aliases"] = merged_aliases

        if not safe_str(existing.get("representative_pattern")).strip():
            existing["representative_pattern"] = generated.get("representative_pattern", "")

        existing["cwe_ids"] = dedupe_keep_order(
            [*safe_list_of_str(existing.get("cwe_ids")), *safe_list_of_str(generated.get("cwe_ids"))]
        )
        existing["representative_code_examples"] = dedupe_keep_order(
            [
                *safe_list_of_str(existing.get("representative_code_examples")),
                *safe_list_of_str(generated.get("representative_code_examples")),
            ]
        )
        existing["common_indicators"] = dedupe_keep_order(
            [
                *safe_list_of_str(existing.get("common_indicators")),
                *safe_list_of_str(generated.get("common_indicators")),
            ]
        )
        return patterns, f"merged_alias_into:{existing.get('name', '')}"

    patterns.append(generated)
    return patterns, f"appended_new:{generated.get('name', '')}"


# =========================
# 결과 파일 처리
# =========================
def collect_unmatched_names(data: list[dict[str, Any]]) -> list[str]:
    unmatched_names_set: set[str] = set()

    for item in data:
        top_vulnerabilities = item.get("top_vulnerabilities", [])
        if not isinstance(top_vulnerabilities, list):
            continue

        for vuln in top_vulnerabilities:
            if not isinstance(vuln, dict):
                continue

            name = safe_str(vuln.get("name")).strip()
            if not name:
                continue

            matched = find_memory_corruption_pattern(name)
            if not matched:
                unmatched_names_set.add(name)

    return sorted(unmatched_names_set, key=lambda x: x.lower())


def remap_output_inplace(data: list[dict[str, Any]]) -> tuple[int, int]:
    matched_vulns = 0
    unmatched_vulns = 0

    for item in data:
        top_vulnerabilities = item.get("top_vulnerabilities", [])
        if not isinstance(top_vulnerabilities, list):
            top_vulnerabilities = []

        new_top_vulnerabilities: list[dict[str, Any]] = []

        for vuln in top_vulnerabilities:
            if not isinstance(vuln, dict):
                continue

            enriched, unmatched_name = enrich_top_vulnerability(vuln)
            new_top_vulnerabilities.append(enriched)

            if unmatched_name:
                unmatched_vulns += 1
            else:
                matched_vulns += 1

        item["top_vulnerabilities"] = new_top_vulnerabilities

    return matched_vulns, unmatched_vulns


def process_output_file(
    output_path: Path,
    patterns_path: Path,
    model_name: str,
    temperature: float,
    dry_run: bool,
) -> None:
    if not output_path.exists():
        raise FileNotFoundError(f"output file not found: {output_path}")
    if not patterns_path.exists():
        raise FileNotFoundError(f"patterns file not found: {patterns_path}")

    with output_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("retriever output JSON must be a list")

    patterns = parse_existing_patterns(patterns_path)
    llm = make_llm(model_name=model_name, temperature=temperature)

    unmatched_names = collect_unmatched_names(data)

    print(f"[INFO] unmatched count before expansion: {len(unmatched_names)}")
    if unmatched_names:
        print("[INFO] unmatched names:")
        for name in unmatched_names:
            print(f"- {name}")

    generated_count = 0
    merge_count = 0
    append_count = 0

    for unmatched_name in unmatched_names:
        print(f"[LLM] generating pattern for: {unmatched_name}")
        generated = generate_pattern_with_llm(llm, unmatched_name)
        patterns, action = merge_or_append_pattern(generated, patterns)
        generated_count += 1

        if action.startswith("merged_alias_into:"):
            merge_count += 1
            print(f"[LLM] merged into existing pattern -> {action}")
        else:
            append_count += 1
            print(f"[LLM] appended new pattern -> {action}")

    if not dry_run:
        write_patterns_file(patterns_path, patterns)
        print(f"[DONE] patterns file overwritten: {patterns_path}")
    else:
        print("[DRY-RUN] patterns file not written")

    # 갱신된 patterns 파일 기준으로 다시 import된 함수가 동작하게 하려면
    # 현재 프로세스 메모리의 리스트도 갱신해둔다.
    MEMORY_CORRUPTION_PATTERNS.clear()
    MEMORY_CORRUPTION_PATTERNS.extend(patterns)

    matched_vulns, unmatched_vulns = remap_output_inplace(data)

    if not dry_run:
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[DONE] output file overwritten: {output_path}")
    else:
        print("[DRY-RUN] output file not written")

    print(f"[SUMMARY] generated with llm: {generated_count}")
    print(f"[SUMMARY] merged into existing: {merge_count}")
    print(f"[SUMMARY] appended as new: {append_count}")
    print(f"[SUMMARY] matched vulnerabilities after remap: {matched_vulns}")
    print(f"[SUMMARY] unmatched vulnerabilities after remap: {unmatched_vulns}")


# =========================
# CLI
# =========================
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Expand memory_corruption_patterns.py with LLM and remap retriever output"
    )
    parser.add_argument(
        "--output-path",
        type=str,
        default="data/retriever_output_top1.json",
        help="Path to retriever output JSON file (will be overwritten)",
    )
    parser.add_argument(
        "--patterns-path",
        type=str,
        default="src/dto/memory_corruption_patterns.py",
        help="Path to memory corruption patterns python file (will be overwritten)",
    )
    parser.add_argument(
        "--model-name",
        type=str,
        default="gpt-4o-mini",
        help="LLM model name for auto-expansion",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.2,
        help="LLM temperature",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not overwrite files; just print what would happen",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    output_path = Path(args.output_path)
    patterns_path = Path(args.patterns_path)

    process_output_file(
        output_path=output_path,
        patterns_path=patterns_path,
        model_name=args.model_name,
        temperature=args.temperature,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()