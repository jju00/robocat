import subprocess
import re
import json
import os
from dataclasses import dataclass
from typing import List, Optional
import argparse


# =========================
# DATA STRUCTURE
# =========================

@dataclass
class FunctionSpan:
    name: str
    start: int
    end: int
    code: str


# =========================
# UTIL
# =========================

def run_cmd(cmd, cwd=None):
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore"
    ).stdout


def git_show(repo, version, path):
    return run_cmd(["git", "show", f"{version}:{path}"], cwd=repo)


def save_diff(repo, old, new, output_dir: str = "."):
    diff = run_cmd(["git", "diff", old, new], cwd=repo)
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "diff.txt"), "w", encoding="utf-8") as f:
        f.write(diff)
    return diff


# =========================
# FILTER
# =========================

def is_c_file(path: str) -> bool:
    path = path.lower()
    return path.endswith(".c") or path.endswith(".cpp") or path.endswith(".cc")


# =========================
# DIFF PARSER
# =========================

def parse_diff(diff_text):
    files = []
    current = None
    old_line = new_line = 0

    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            if current:
                files.append(current)

            path = line.split(" b/")[-1]
            current = {
                "file_path": path,
                "added": [],
                "deleted": []
            }

        elif line.startswith("@@"):
            m = re.search(r"\-(\d+).+\+(\d+)", line)
            if m:
                old_line = int(m.group(1))
                new_line = int(m.group(2))

        elif line.startswith("+") and not line.startswith("+++"):
            current["added"].append(new_line)
            new_line += 1

        elif line.startswith("-") and not line.startswith("---"):
            current["deleted"].append(old_line)
            old_line += 1

        else:
            old_line += 1
            new_line += 1

    if current:
        files.append(current)

    return files


# =========================
# FUNCTION EXTRACTOR (안정화)
# =========================

CONTROL_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "do"}

def extract_c(code: str) -> List[FunctionSpan]:
    lines = code.splitlines()
    spans = []

    i = 0
    while i < len(lines):
        line = lines[i]

        if "(" not in line:
            i += 1
            continue

        header = line
        j = i

        # 🔥 안전한 multi-line 처리
        while True:
            if j >= len(lines):
                break

            if "{" in lines[j]:
                break

            if ";" in lines[j]:
                break

            j += 1

            if j < len(lines):
                header += " " + lines[j].strip()

            if j - i > 10:
                break

        if j >= len(lines):
            i += 1
            continue

        if "{" not in lines[j]:
            i += 1
            continue

        # 함수 이름 추출
        matches = re.findall(r"([A-Za-z_]\w*)\s*\(", header)
        if not matches:
            i += 1
            continue

        fname = matches[-1]

        # 필터
        if fname in CONTROL_KEYWORDS:
            i += 1
            continue

        if fname.isupper():
            i += 1
            continue

        # 본문 추출
        start = i + 1
        brace = 0
        k = j
        opened = False

        while k < len(lines):
            brace += lines[k].count("{")
            brace -= lines[k].count("}")

            if "{" in lines[k]:
                opened = True

            if opened and brace == 0:
                end = k + 1
                code_block = "\n".join(lines[start - 1:end]) + "\n"

                spans.append(FunctionSpan(
                    fname,
                    start,
                    end,
                    code_block
                ))
                break

            k += 1

        i = max(k + 1, i + 1)

    return spans


# =========================
# MAPPING
# =========================

def find_function(spans: List[FunctionSpan], line: int) -> Optional[FunctionSpan]:
    for sp in spans:
        if sp.start <= line <= sp.end:
            return sp
    return None


# =========================
# MAIN
# =========================

def run(repo, old, new, output_dir: str = "."):
    id_counter = 1
    diff = save_diff(repo, old, new, output_dir=output_dir)
    parsed = parse_diff(diff)

    result = {
        "project": os.path.basename(repo),
        "from_version": old,
        "test_version": new,
        "files": []
    }

    for f in parsed:
        path = f["file_path"]

        # 🔥 핵심 필터
        if not is_c_file(path):
            continue

        before = git_show(repo, old, path)
        after = git_show(repo, new, path)

        before_funcs = extract_c(before)
        after_funcs = extract_c(after)

        print(f"[DEBUG] {path} → {len(before_funcs)} / {len(after_funcs)} functions")

        func_names = set()

        for ln in f["added"]:
            sp = find_function(after_funcs, ln)
            if sp:
                func_names.add(sp.name)

        for ln in f["deleted"]:
            sp = find_function(before_funcs, ln)
            if sp:
                func_names.add(sp.name)

        funcs = []

        for name in sorted(func_names):
            before_sp = next((x for x in before_funcs if x.name == name), None)
            after_sp = next((x for x in after_funcs if x.name == name), None)

            before_code = before_sp.code if before_sp else ""
            after_code = after_sp.code if after_sp else ""

            if not before_code and not after_code:
                continue

            funcs.append({
                "id":id_counter,
                "function": name,
                "start": before_sp.start if before_sp else after_sp.start,
                "end": before_sp.end if before_sp else after_sp.end,
                "code_before_change": before_code,
                "code_after_change": after_code
            })
            id_counter += 1

        if funcs:
            result["files"].append({
                "file_path": path,
                "functions": funcs
            })

    out_path = os.path.join(output_dir, "diff_functions.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(f"diff.txt → {os.path.join(output_dir, 'diff.txt')}")
    print(f"diff_functions.json → {out_path}")


# =========================
# CLI
# =========================

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--old", required=True)
    parser.add_argument("--new", required=True)
    parser.add_argument("--output-dir", default=".", help="diff.txt / diff_functions.json 저장 디렉토리")

    args = parser.parse_args()

    run(args.repo, args.old, args.new, output_dir=args.output_dir)