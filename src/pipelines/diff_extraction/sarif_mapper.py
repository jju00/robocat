import json
import os
from typing import Dict, List

# =========================
# SARIF LOADER
# =========================

def load_sarif(path: str) -> Dict[str, List[int]]:
    """
    SARIF → { filename: [line, ...] }
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    index = {}

    for run in data.get("runs", []):
        for res in run.get("results", []):
            locs = res.get("locations", [])
            if not locs:
                continue

            phys = locs[0]["physicalLocation"]
            uri = phys["artifactLocation"]["uri"]
            line = phys["region"]["startLine"]

            base = os.path.basename(uri)

            index.setdefault(base, set()).add(line)

    # set → sorted list
    return {k: sorted(list(v)) for k, v in index.items()}


# =========================
# FUNCTION VALIDATION
# =========================

def is_valid_function(name: str, code: str) -> bool:
    """
    garbage 함수 제거
    """
    if not name or name == "<global>":
        return False

    # 매크로 제거
    if name.isupper():
        return False

    # 기본 필터
    blacklist = ["endif", "define", "typedef"]
    if name in blacklist:
        return False

    # 최소 함수 형태 확인
    if "(" not in code or ")" not in code:
        return False

    return True


# =========================
# LINE RANGE EXTRACTOR (중요)
# =========================

def extract_line_range(code: str):
    """
    코드 블록 길이 기반으로 대략적인 line 범위 추정
    (diff_functions.json에 start/end 없기 때문에)
    """
    lines = code.splitlines()
    return len(lines)


# =========================
# MAPPING CORE
# =========================

def map_sarif(diff_path: str, sarif_path: str, output_path="diff_sarif.json"):
    diff_data = json.load(open(diff_path))
    sarif_index = load_sarif(sarif_path)

    output = {"files": []}

    for file_entry in diff_data.get("files", []):
        file_path = file_entry["file_path"]
        base = os.path.basename(file_path)

        file_hits = sarif_index.get(base, [])

        # 🔥 파일 단위에서도 SARIF 없으면 skip
        if not file_hits:
            continue

        new_functions = []

        for func in file_entry.get("functions", []):
            name = func["function"]
            before = func["code_before_change"]
            after = func["code_after_change"]

            merged_code = (before or "") + "\n" + (after or "")

            # 🔥 1. 함수 필터
            if not is_valid_function(name, merged_code):
                continue

            # 🔥 2. 라인 기반 필터 (간단 but 효과적)
            code_len = extract_line_range(merged_code)

            # heuristic: 너무 작은 블록은 제외
            if code_len < 3:
                continue

            start = func.get("start")
            end = func.get("end")

            if start is None or end is None:
                continue

            hits = [h for h in file_hits if start <= h <= end]

            if not hits:
                continue

            # 🔥 4. 중복 제거 + 정렬
            hits = sorted(set(hits))

            new_functions.append({
                "function": name,
                "code_before_change": before,
                "code_after_change": after,
                "sarif_hits": hits
            })

        if new_functions:
            output["files"].append({
                "file_path": file_path,
                "functions": new_functions
            })

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"✅ diff_sarif.json 생성 완료 → {output_path}")


# =========================
# CLI
# =========================

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--diff", required=True, help="diff_functions.json")
    p.add_argument("--sarif", required=True, help="result.sarif")

    args = p.parse_args()

    map_sarif(args.diff, args.sarif)