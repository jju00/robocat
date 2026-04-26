import argparse
import json
import shutil
from pathlib import Path
from collections import defaultdict


def iter_json_objects(path: Path):
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [obj for obj in data if isinstance(obj, dict)]
    return []


def write_json_array_stream(out_path: Path, items, global_counter: list) -> int:
    """items를 JSON 배열로 저장하고 전역 id를 순차 부여. 작성된 항목 수 반환."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with out_path.open("w", encoding="utf-8") as f:
        f.write("[\n")
        first = True
        for item in items:
            global_counter[0] += 1
            item["id"] = global_counter[0]
            if not first:
                f.write(",\n")
            f.write(json.dumps(item, ensure_ascii=False, indent=2))
            first = False
            written += 1
        f.write("\n]\n")
    return written


def write_jsonl(out_path: Path, items, global_counter: list) -> int:
    """items를 JSONL로 저장하고 전역 id를 순차 부여. 작성된 항목 수 반환."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with out_path.open("w", encoding="utf-8") as f:
        for item in items:
            global_counter[0] += 1
            item["id"] = global_counter[0]
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
            written += 1
    return written


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_dir", required=True, help="e.g. ./data/train")
    ap.add_argument("--lang", required=True, choices=["php", "c", "cpp"])
    ap.add_argument("--format", choices=["json", "jsonl"], default="json")
    ap.add_argument("--exclude_unknown", action="store_true")
    ap.add_argument("--delete_cwe_dirs", action="store_true", help="merge 후 기존 CWE 폴더 삭제")
    args = ap.parse_args()

    lang_dir = Path(args.in_dir).expanduser() / args.lang
    lang_dir.mkdir(parents=True, exist_ok=True)

    # CWE -> list of CVE json file paths
    buckets = defaultdict(list)

    for cwe_dir in lang_dir.iterdir():
        if not cwe_dir.is_dir():
            continue

        cwe = cwe_dir.name
        if args.exclude_unknown and "unknown" in cwe.lower():
            continue

        json_files = sorted(cwe_dir.glob("*.json"), key=lambda x: x.name)
        for p in json_files:
            buckets[cwe].append(p)

    total_in = sum(len(v) for v in buckets.values())
    print(f"[{args.lang}] Found CWE folders: {len(buckets)}")
    print(f"[{args.lang}] Found input CVE json files (after filters): {total_in}")

    global_counter = [0]
    total_written = 0

    for cwe, paths in sorted(buckets.items()):
        paths = sorted(paths, key=lambda x: x.name)

        def items_gen():
            for p in paths:
                for obj in iter_json_objects(p):
                    yield obj

        out_path = lang_dir / f"{cwe}.{args.format}"
        if args.format == "json":
            written = write_json_array_stream(out_path, items_gen(), global_counter)
        else:
            written = write_jsonl(out_path, items_gen(), global_counter)

        total_written += written
        print(
            f"Wrote {out_path} "
            f"({written} items, id {global_counter[0] - written + 1}~{global_counter[0]})"
        )

    if args.delete_cwe_dirs:
        for cwe_dir in lang_dir.iterdir():
            if not cwe_dir.is_dir():
                continue
            if args.exclude_unknown and "unknown" in cwe_dir.name.lower():
                continue
            shutil.rmtree(cwe_dir)
            print(f"Deleted directory: {cwe_dir}")

    print(
        f"\nDone [{args.lang}]. "
        f"Total items: {total_written}, "
        f"Global id range: 1~{global_counter[0]}"
    )


if __name__ == "__main__":
    main()