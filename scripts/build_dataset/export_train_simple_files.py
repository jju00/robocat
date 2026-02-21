import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import difflib
import ast
from tqdm import tqdm
import os

# 프로젝트 루트를 path에 추가
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from src.dto.rawdiffdto import RawDiffDTO, FunctionModifiedLinesDTO

BAD_CWE = {"NVD-CWE-Other", "NVD-CWE-noinfo", "CWE-Other", "CWE-noinfo"}

def table_columns(conn: sqlite3.Connection, table: str) -> List[str]:
    cur = conn.execute(f"PRAGMA table_info({table});")
    return [row[1] for row in cur.fetchall()]

def pick_first(cols: List[str], candidates: List[str]) -> Optional[str]:
    s = set(cols)
    for c in candidates:
        if c in s:
            return c
    return None

def build_cwe_map(conn: sqlite3.Connection) -> Dict[str, List[str]]:
    cwe_map: Dict[str, List[str]] = {}
    cols = table_columns(conn, "cwe_classification")
    cve_col = pick_first(cols, ["cve_id", "cve"])
    cwe_col = pick_first(cols, ["cwe_id", "cwe", "cwe_code", "cwe_name"])
    if not cve_col or not cwe_col:
        return cwe_map

    cur = conn.execute(f"SELECT {cve_col}, {cwe_col} FROM cwe_classification;")
    for cve_id, cwe_val in cur.fetchall():
        if cve_id is None or cwe_val is None:
            continue
        cwe_str = str(cwe_val).strip()
        if not cwe_str or cwe_str in BAD_CWE:
            continue
        cve_id = str(cve_id)
        cwe_map.setdefault(cve_id, [])
        if cwe_str not in cwe_map[cve_id]:
            cwe_map[cve_id].append(cwe_str)
    return cwe_map

def primary_cwe(cwes: List[str]) -> str:
    c = [x for x in (cwes or []) if isinstance(x, str) and x.startswith("CWE-") and x not in BAD_CWE]
    return sorted(set(c))[0] if c else "CWE-Unknown"

def normalize_description(desc: Optional[str]) -> str:
    if not desc:
        return ""
    s = str(desc).strip()
    if not (s.startswith("[") and "lang" in s and "value" in s):
        return s
    try:
        obj = ast.literal_eval(s)
        if isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict) and item.get("lang") == "en" and "value" in item:
                    return str(item["value"])
        return s
    except Exception:
        return s

def safe_int(x: object, default: int = 0) -> int:
    try:
        return int(str(x))
    except Exception:
        return default

def slice_lines(text: str, start_line: int, end_line: int, expand: int = 0) -> str:
    if text is None:
        return ""
    lines = str(text).splitlines()
    if not lines:
        return ""
    s = max(1, start_line)
    e = max(s, end_line + max(0, expand))
    s_idx = min(len(lines), s) - 1
    e_idx = min(len(lines), e)
    return "\n".join(lines[s_idx:e_idx])

def looks_like_code(text: str, min_lines: int = 3, min_chars: int = 20) -> bool:
    if text is None:
        return False
    t = str(text)
    stripped = t.strip()
    if stripped in {"True", "False", "0", "1", "None", "NULL"}:
        return False
    if (t.count("\n") + 1) < min_lines:
        return False
    if len(stripped) < min_chars:
        return False
    return True

def compute_modified_lines(before_code: str, after_code: str, drop_ws_only: bool = True) -> Tuple[List[str], List[str]]:
    before_lines = before_code.splitlines()
    after_lines = after_code.splitlines()
    sm = difflib.SequenceMatcher(a=before_lines, b=after_lines, autojunk=False)

    added: List[str] = []
    deleted: List[str] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "insert":
            added.extend(after_lines[j1:j2])
        elif tag == "delete":
            deleted.extend(before_lines[i1:i2])
        elif tag == "replace":
            deleted.extend(before_lines[i1:i2])
            added.extend(after_lines[j1:j2])

    if drop_ws_only:
        added = [ln for ln in added if ln.strip() != ""]
        deleted = [ln for ln in deleted if ln.strip() != ""]
    return added, deleted

def atomic_write(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--out_dir", default="~/cve_work/export/train_simple")
    ap.add_argument("--limit_rows", type=int, default=0)
    ap.add_argument("--lang", type=str, default="", help="e.g., PHP, C")
    ap.add_argument("--min_code_lines", type=int, default=3)
    ap.add_argument("--expand_end", type=int, default=0)
    ap.add_argument("--drop_ws_only", action="store_true")
    ap.add_argument("--require_name_in_code", action="store_true")
    args = ap.parse_args()

    out_dir = Path(os.path.expanduser(args.out_dir))
    out_dir.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(Path(args.db)))
    conn.row_factory = sqlite3.Row

    cwe_map = build_cwe_map(conn)

    sql = """
    SELECT
        fx.cve_id      AS cve_id,
        cv.description AS cve_description,
        fc.diff        AS patch,
        fc.code_before AS file_code_before,
        fc.code_after  AS file_code_after,
        mc.name        AS method_name,
        mc.start_line  AS start_line,
        mc.end_line    AS end_line
    FROM method_change mc
    JOIN file_change fc
      ON mc.file_change_id = fc.file_change_id
    JOIN fixes fx
      ON fx.hash = fc.hash
    JOIN cve cv
      ON cv.cve_id = fx.cve_id
    WHERE fc.code_before IS NOT NULL
      AND fc.code_after IS NOT NULL
      AND mc.start_line IS NOT NULL
      AND mc.end_line IS NOT NULL
      AND (mc.before_change = 1 OR mc.before_change = 'True')
    """
    params: List[object] = []
    if args.lang:
        sql += " AND fc.programming_language = ?"
        params.append(args.lang)
    if args.limit_rows and args.limit_rows > 0:
        sql += " LIMIT ?"
        params.append(args.limit_rows)

    cur = conn.execute(sql, params)

    # 메모리에는 카운터/CWE 정보만 보관 (정수 + 짧은 문자열 → 수 MB 이하)
    cve_counter: Dict[str, int] = {}   # cve_id -> 현재까지 쓴 항목 수
    cve_cwes: Dict[str, List[str]] = {}

    skipped = 0
    total_written = 0

    for row in tqdm(cur, desc="Exporting", unit="rows"):
        cve_id = str(row["cve_id"])

        start_line = safe_int(row["start_line"], 0)
        end_line = safe_int(row["end_line"], 0)
        if start_line <= 0 or end_line <= 0 or end_line < start_line:
            skipped += 1
            continue

        before_code = slice_lines(row["file_code_before"], start_line, end_line, expand=args.expand_end)
        after_code = slice_lines(row["file_code_after"], start_line, end_line, expand=args.expand_end)

        if not looks_like_code(before_code, min_lines=args.min_code_lines) or not looks_like_code(after_code, min_lines=args.min_code_lines):
            skipped += 1
            continue

        if args.require_name_in_code:
            mn = (row["method_name"] or "").strip()
            if mn and (mn not in before_code or mn not in after_code):
                skipped += 1
                continue

        added, deleted = compute_modified_lines(before_code, after_code, drop_ws_only=args.drop_ws_only)
        if not added and not deleted:
            skipped += 1
            continue

        cwes = cwe_map.get(cve_id, [])
        if cve_id not in cve_cwes:
            cve_cwes[cve_id] = cwes

        # id 순차 부여
        cve_counter[cve_id] = cve_counter.get(cve_id, 0) + 1

        dto = RawDiffDTO(
            cve_id=cve_id,
            code_before_change=before_code,
            code_after_change=after_code,
            patch=row["patch"] or "",
            function_modified_lines=FunctionModifiedLinesDTO(added=added, deleted=deleted),
            cwe=cwes,
            cve_description=normalize_description(row["cve_description"]),
            id=cve_counter[cve_id],
        )

        # 처리 즉시 JSONL로 디스크에 append (메모리에 쌓지 않음)
        folder = primary_cwe(cwes)
        jsonl_path = out_dir / folder / f"{cve_id}.jsonl"
        jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        with jsonl_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(dto.model_dump(), ensure_ascii=False) + "\n")

        total_written += 1

    conn.close()

    # JSONL → JSON 변환 (CVE 1개씩 처리 → 메모리 안전)
    print(f"\nConverting {len(cve_counter)} CVE JSONL files to JSON...")
    for cve_id, cwes in tqdm(cve_cwes.items(), desc="Converting to JSON", unit="cve"):
        folder = primary_cwe(cwes)
        jsonl_path = out_dir / folder / f"{cve_id}.jsonl"
        json_path  = out_dir / folder / f"{cve_id}.json"

        items = [
            json.loads(line)
            for line in jsonl_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        atomic_write(json_path, items)
        jsonl_path.unlink()  # 임시 파일 정리

    print(f"Done. CVE files written: {len(cve_counter)}, Total items: {total_written}, Skipped rows: {skipped}, Out: {out_dir}")

if __name__ == "__main__":
    main()
