import subprocess
import re
import json
from dataclasses import dataclass
from typing import List, Optional, Set


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
# GIT
# =========================

def git_show(repo, version, path):
    result = subprocess.run(
        ["git", "show", f"{version}:{path}"],
        cwd=repo,
        capture_output=True,
        text=True
    )
    return result.stdout


# =========================
# LANGUAGE DETECTOR
# =========================

def detect_language(path: str):
    if path.endswith(".php"):
        return "php"
    if path.endswith(".py"):
        return "python"
    if path.endswith(".js") or path.endswith(".ts"):
        return "javascript"
    if path.endswith(".java"):
        return "java"
    if path.endswith(".cs"):
        return "csharp"
    if path.endswith(".c"):
        return "c"
    if path.endswith(".cpp") or path.endswith(".cc") or path.endswith(".hpp"):
        return "cpp"
    return "unknown"


# =========================
# PHP EXTRACTOR
# =========================

PHP_FUNC_RE = re.compile(
    r"^\s*(public|protected|private|static|\s)*\s*function\s+&?\s*([a-zA-Z_]\w*)\s*\(",
    re.MULTILINE
)

PHP_CLASS_RE = re.compile(
    r"^\s*(class|trait|interface)\s+([a-zA-Z_]\w*)",
    re.MULTILINE
)

def extract_php(code: str):
    lines = code.splitlines()
    spans = []
    class_name = None

    i = 0
    while i < len(lines):
        line = lines[i]

        cm = PHP_CLASS_RE.match(line)
        if cm:
            class_name = cm.group(2)

        fm = PHP_FUNC_RE.match(line)
        if fm:
            fname = fm.group(2)
            full = f"{class_name}::{fname}" if class_name else fname

            start = i + 1
            brace = 0
            j = i
            found = False

            while j < len(lines):
                if "{" in lines[j]:
                    brace += lines[j].count("{")
                    found = True
                if "}" in lines[j]:
                    brace -= lines[j].count("}")
                    if found and brace == 0:
                        end = j + 1
                        code_block = "\n".join(lines[start-1:end]) + "\n"
                        spans.append(FunctionSpan(full, start, end, code_block))
                        break
                j += 1

            i = j
        else:
            i += 1

    return spans


# =========================
# PYTHON EXTRACTOR
# =========================

def extract_python(code: str):
    lines = code.splitlines()
    spans = []

    for i, line in enumerate(lines):
        m = re.match(r"^\s*def\s+([a-zA-Z_]\w*)\s*\(", line)
        if m:
            fname = m.group(1)
            start = i + 1
            indent = len(line) - len(line.lstrip())

            j = i + 1
            while j < len(lines):
                if lines[j].strip() == "":
                    j += 1
                    continue

                cur_indent = len(lines[j]) - len(lines[j].lstrip())
                if cur_indent <= indent:
                    break
                j += 1

            end = j
            code_block = "\n".join(lines[start-1:end]) + "\n"
            spans.append(FunctionSpan(fname, start, end, code_block))

    return spans


# =========================
# JAVASCRIPT EXTRACTOR
# =========================

JS_FUNC_RE = re.compile(
    r"(function\s+([a-zA-Z_]\w*)\s*\(|([a-zA-Z_]\w*)\s*=\s*\(.*?\)\s*=>)",
    re.MULTILINE
)

def extract_js(code: str):
    lines = code.splitlines()
    spans = []

    for i, line in enumerate(lines):
        m = JS_FUNC_RE.search(line)
        if m:
            fname = m.group(2) or m.group(3) or "anonymous"
            start = i + 1

            brace = 0
            j = i
            found = False

            while j < len(lines):
                if "{" in lines[j]:
                    brace += lines[j].count("{")
                    found = True
                if "}" in lines[j]:
                    brace -= lines[j].count("}")
                    if found and brace == 0:
                        end = j + 1
                        code_block = "\n".join(lines[start-1:end]) + "\n"
                        spans.append(FunctionSpan(fname, start, end, code_block))
                        break
                j += 1

    return spans


# =========================
# C / C++ EXTRACTOR
# =========================

C_FUNC_RE = re.compile(
    r"^\s*([a-zA-Z_][\w\s\*\&]+)\s+([a-zA-Z_]\w*)\s*\([^;]*\)\s*\{",
    re.MULTILINE
)

def extract_c(code: str):
    lines = code.splitlines()
    spans = []

    for i, line in enumerate(lines):
        m = C_FUNC_RE.match(line)
        if m:
            fname = m.group(2)
            start = i + 1

            brace = 0
            j = i
            found = False

            while j < len(lines):
                if "{" in lines[j]:
                    brace += lines[j].count("{")
                    found = True
                if "}" in lines[j]:
                    brace -= lines[j].count("}")
                    if found and brace == 0:
                        end = j + 1
                        code_block = "\n".join(lines[start-1:end]) + "\n"
                        spans.append(FunctionSpan(fname, start, end, code_block))
                        break
                j += 1

    return spans


# =========================
# JAVA EXTRACTOR
# =========================

JAVA_FUNC_RE = re.compile(
    r"^\s*(public|protected|private|static|\s)*\s+[a-zA-Z_<>\[\]]+\s+([a-zA-Z_]\w*)\s*\(",
    re.MULTILINE
)

JAVA_CLASS_RE = re.compile(r"class\s+([A-Za-z_]\w*)")

def extract_java(code: str):
    lines = code.splitlines()
    spans = []
    class_name = None

    for i, line in enumerate(lines):
        cm = JAVA_CLASS_RE.search(line)
        if cm:
            class_name = cm.group(1)

        fm = JAVA_FUNC_RE.match(line)
        if fm:
            fname = fm.group(2)
            full = f"{class_name}::{fname}" if class_name else fname

            start = i + 1
            brace = 0
            j = i
            found = False

            while j < len(lines):
                if "{" in lines[j]:
                    brace += lines[j].count("{")
                    found = True
                if "}" in lines[j]:
                    brace -= lines[j].count("}")
                    if found and brace == 0:
                        end = j + 1
                        code_block = "\n".join(lines[start-1:end]) + "\n"
                        spans.append(FunctionSpan(full, start, end, code_block))
                        break
                j += 1

    return spans


# =========================
# C# EXTRACTOR
# =========================

CS_FUNC_RE = re.compile(
    r"^\s*(public|private|protected|static|\s)+\s+[a-zA-Z_<>\[\]]+\s+([a-zA-Z_]\w*)\s*\(",
    re.MULTILINE
)

CS_CLASS_RE = re.compile(r"class\s+([A-Za-z_]\w*)")

def extract_csharp(code: str):
    lines = code.splitlines()
    spans = []
    class_name = None

    for i, line in enumerate(lines):
        cm = CS_CLASS_RE.search(line)
        if cm:
            class_name = cm.group(1)

        fm = CS_FUNC_RE.match(line)
        if fm:
            fname = fm.group(2)
            full = f"{class_name}::{fname}" if class_name else fname

            start = i + 1
            brace = 0
            j = i
            found = False

            while j < len(lines):
                if "{" in lines[j]:
                    brace += lines[j].count("{")
                    found = True
                if "}" in lines[j]:
                    brace -= lines[j].count("}")
                    if found and brace == 0:
                        end = j + 1
                        code_block = "\n".join(lines[start-1:end]) + "\n"
                        spans.append(FunctionSpan(full, start, end, code_block))
                        break
                j += 1

    return spans


# =========================
# EXTRACTOR REGISTRY
# =========================

def get_extractor(lang):
    return {
        "php": extract_php,
        "python": extract_python,
        "javascript": extract_js,
        "java": extract_java,
        "c": extract_c,
        "cpp": extract_c,
        "csharp": extract_csharp
    }.get(lang)


# =========================
# DIFF PARSER
# =========================

def parse_diff(diff_text):
    files = []
    current = None
    new_line = 0
    old_line = 0

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
            m = re.search(r"\-(\d+),?\d*\s+\+(\d+)", line)
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
# MAPPING
# =========================

def find_function(spans, line):
    for sp in spans:
        if sp.start <= line <= sp.end:
            return sp.name
    return "<global>"


# =========================
# MAIN
# =========================

def run(repo, old, new):
    diff = subprocess.run(
        ["git", "diff", old, new],
        cwd=repo,
        capture_output=True,
        text=True
    ).stdout

    parsed = parse_diff(diff)

    result = {
        "project": repo,
        "from_version": old,
        "test_version": new,
        "files": []
    }

    for file in parsed:
        path = file["file_path"]

        if "vendor" in path or path.endswith(".min.js"):
            continue

        lang = detect_language(path)
        extractor = get_extractor(lang)

        if extractor is None:
            continue

        before_code = git_show(repo, old, path)
        after_code = git_show(repo, new, path)

        before_funcs = extractor(before_code)
        after_funcs = extractor(after_code)

        changed_funcs: Set[str] = set()

        for ln in file["added"]:
            changed_funcs.add(find_function(after_funcs, ln))

        for ln in file["deleted"]:
            changed_funcs.add(find_function(before_funcs, ln))

        func_list = []

        for fname in changed_funcs:
            bf = next((f for f in before_funcs if f.name == fname), None)
            af = next((f for f in after_funcs if f.name == fname), None)

            before_code = bf.code if bf else ""
            after_code = af.code if af else ""

            # 🔥 필터링
            if fname == "<global>" and not before_code and not after_code:
                continue
            if not before_code and not after_code:
                continue
            if before_code.strip() == after_code.strip():
                continue

            func_list.append({
                "function": fname,
                "code_before_change": before_code,
                "code_after_change": after_code
            })

        if func_list:
            result["files"].append({
                "file_path": path,
                "lang": lang,
                "functions": func_list
            })

    return result


# =========================
# CLI
# =========================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--old", required=True)
    parser.add_argument("--new", required=True)
    parser.add_argument("--out", default="diff_functions.json")

    args = parser.parse_args()

    output = run(args.repo, args.old, args.new)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print("[+] Done →", args.out)