import argparse
import json
from pathlib import Path
from collections import defaultdict

def iter_json_objects(path: Path):
    # 각 파일은 [ { ... }, { ... }, ... ] 형태 — 모든 항목 반환
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [obj for obj in data if isinstance(obj, dict)]
    return []

def write_json_array_stream(out_path: Path, items):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        f.write("[\n")
        first = True
        for item in items:
            if not first:
                f.write(",\n")
            f.write(json.dumps(item, ensure_ascii=False))
            first = False
        f.write("\n]\n")

def write_jsonl(out_path: Path, items):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_dir", required=True, help="e.g. ~/cve_work/export/train_simple")
    ap.add_argument("--out_dir", required=True, help="e.g. ~/cve_work/export/train_merged")
    ap.add_argument("--format", choices=["json", "jsonl"], default="jsonl")
    ap.add_argument("--exclude_unknown", action="store_true")
    args = ap.parse_args()

    in_dir = Path(args.in_dir).expanduser()
    out_dir = Path(args.out_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)

    # CWE -> list of file paths
    buckets = defaultdict(list)
    for p in in_dir.rglob("*.json"):
        # .../train_simple/CWE-xxx/CVE-xxxx.json
        if len(p.parts) < 2:
            continue
        cwe = p.parent.name
        if args.exclude_unknown and "unknown" in cwe.lower():
            continue
        buckets[cwe].append(p)

    total_in = sum(len(v) for v in buckets.values())
    print(f"Found CWE folders: {len(buckets)}")
    print(f"Found input CVE json files (after filters): {total_in}")

    for cwe, paths in sorted(buckets.items()):
        # CVE 기준 정렬(파일명 기준)
        paths = sorted(paths, key=lambda x: x.name)

        def items_gen():
            for p in paths:
                for obj in iter_json_objects(p):
                    yield obj

        out_path = out_dir / f"{cwe}.{args.format}"
        if args.format == "json":
            write_json_array_stream(out_path, items_gen())
        else:
            write_jsonl(out_path, items_gen())

        print(f"Wrote {out_path} (from {len(paths)} files)")

if __name__ == "__main__":
    main()
