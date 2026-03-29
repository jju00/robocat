import argparse
import json
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Set


# -----------------------------
# Git helpers
# -----------------------------
def run_git(repo_path: str, args: List[str]) -> str:
    res = subprocess.run(
        ["git"] + args,
        cwd=repo_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if res.returncode != 0:
        raise RuntimeError(
            f"Git command failed: git {' '.join(args)}\n"
            f"stdout:\n{res.stdout}\n\nstderr:\n{res.stderr}"
        )
    return res.stdout


def git_show_file(repo_path: str, version: str, file_path: str) -> str:
    try:
        return run_git(repo_path, ["show", f"{version}:{file_path}"])
    except Exception:
        return ""


def git_changed_files(repo_path: str, old_ver: str, new_ver: str) -> List[str]:
    out = run_git(repo_path, ["diff", "--name-only", old_ver, new_ver])
    return [x.strip() for x in out.splitlines() if x.strip()]


def git_diff_file(repo_path: str, old_ver: str, new_ver: str, file_path: str, unified: int = 3) -> str:
    return run_git(repo_path, ["diff", f"-U{unified}", old_ver, new_ver, "--", file_path])

def save_full_diff(repo_path: str, old_ver: str, new_ver: str, output="diff.txt"):
    diff = run_git(repo_path, ["diff", old_ver, new_ver])
    
    with open(output, "w", encoding="utf-8") as f:
        f.write(diff)

    print(f"[+] wrote {output}")

# -----------------------------
# Diff parsing
# -----------------------------
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass(frozen=True)
class TouchedLines:
    new_lines: Set[int]
    old_lines: Set[int]


def parse_touched_lines(diff_text: str) -> TouchedLines:
    new_lines: Set[int] = set()
    old_lines: Set[int] = set()

    cur_old = 0
    cur_new = 0

    for raw in diff_text.splitlines():

        if raw.startswith("@@"):
            m = HUNK_RE.match(raw)
            if m:
                cur_old = int(m.group(1))
                cur_new = int(m.group(3))
            continue

        if raw.startswith("+") and not raw.startswith("+++"):
            new_lines.add(cur_new)
            cur_new += 1
            continue

        if raw.startswith("-") and not raw.startswith("---"):
            old_lines.add(cur_old)
            cur_old += 1
            continue

        if raw.startswith(" "):
            cur_old += 1
            cur_new += 1
            continue

    return TouchedLines(new_lines=new_lines, old_lines=old_lines)


# -----------------------------
# PHP function span extraction
# -----------------------------
PHP_CLASS_RE = re.compile(r"^\s*(?:final\s+|abstract\s+)?class\s+([A-Za-z_]\w*)\b")

PHP_FUNCTION_RE = re.compile(
    r"""^\s*
        (?:(?:public|protected|private|static|final|abstract)\s+)*
        function\s+&?\s*([A-Za-z_]\w*)\s*\(
    """,
    re.VERBOSE,
)


def strip_strings_rough(line: str) -> str:
    line = re.sub(r"'.*?(?<!\\)'", "''", line)
    line = re.sub(r'".*?(?<!\\)"', '""', line)
    return line


def count_braces_rough(line: str) -> Tuple[int, int]:
    s = strip_strings_rough(line)
    return s.count("{"), s.count("}")


@dataclass
class FunctionSpan:
    full_name: str
    short_name: str
    start_line: int
    end_line: int


def extract_php_function_spans(code: str) -> List[FunctionSpan]:

    if not code:
        return []

    lines = code.splitlines()
    spans: List[FunctionSpan] = []

    brace_depth = 0
    class_stack: List[Tuple[str, int]] = []
    pending_class: Optional[str] = None

    i = 0
    while i < len(lines):

        line = lines[i]
        line_no = i + 1

        cm = PHP_CLASS_RE.match(strip_strings_rough(line))
        if cm:
            pending_class = cm.group(1)

        opens, closes = count_braces_rough(line)

        if pending_class and opens > 0:
            class_stack.append((pending_class, brace_depth))
            pending_class = None

        current_class = class_stack[-1][0] if class_stack else None

        fm = PHP_FUNCTION_RE.match(strip_strings_rough(line))

        if fm:
            fname = fm.group(1)
            func_sig_line = line_no
            func_class = current_class

            j = i
            found_body = False
            body_line = None

            while j < len(lines):

                s = strip_strings_rough(lines[j])

                if "{" in s:
                    found_body = True
                    body_line = j + 1
                    break

                if ";" in s and "{" not in s:
                    break

                j += 1

            if not found_body:
                i += 1
                brace_depth += opens
                brace_depth -= closes
                continue

            func_depth = 0
            started = False
            end_line = body_line

            k = body_line - 1

            while k < len(lines):

                s = strip_strings_rough(lines[k])

                for ch in s:

                    if ch == "{":
                        func_depth += 1
                        started = True

                    elif ch == "}":
                        if started:
                            func_depth -= 1
                            if func_depth == 0:
                                end_line = k + 1
                                k = len(lines)
                                break

                if k < len(lines):
                    end_line = k + 1

                k += 1

            full_name = f"{func_class}::{fname}" if func_class else fname

            spans.append(
                FunctionSpan(
                    full_name=full_name,
                    short_name=fname,
                    start_line=func_sig_line,
                    end_line=end_line,
                )
            )

        brace_depth += opens
        brace_depth -= closes

        if brace_depth < 0:
            brace_depth = 0

        while class_stack and brace_depth <= class_stack[-1][1]:
            class_stack.pop()

        i += 1

    return spans


# -----------------------------
# span lookup (IMPROVED)
# -----------------------------
def find_enclosing_span(spans: List[FunctionSpan], line_no: int) -> Optional[FunctionSpan]:

    for sp in spans:

        if sp.start_line - 3 <= line_no <= sp.end_line:
            return sp

    return None


def slice_lines(code: str, start_line: int, end_line: int) -> str:

    lines = code.splitlines()

    s = max(0, start_line - 1)
    e = min(len(lines), end_line)

    return ("\n".join(lines[s:e]).rstrip() + "\n") if s < e else ""


# -----------------------------
# GLOBAL snippet
# -----------------------------
def extract_global_snippet(code: str, touched_lines: Set[int], context: int = 8) -> str:

    if not code or not touched_lines:
        return ""

    lines = code.splitlines()
    n = len(lines)

    ranges = []

    for l in sorted(touched_lines):

        a = max(1, l - context)
        b = min(n, l + context)

        ranges.append((a, b))

    merged = []

    for a, b in ranges:

        if not merged or a > merged[-1][1] + 1:
            merged.append([a, b])
        else:
            merged[-1][1] = max(merged[-1][1], b)

    chunks = []

    for a, b in merged:

        chunk = "\n".join(lines[a - 1 : b]).rstrip()

        chunks.append(f"/* lines {a}-{b} */\n{chunk}\n")

    return "\n".join(chunks).rstrip() + "\n"


# -----------------------------
# PHPDoc-only filter
# -----------------------------
def is_phpdoc_only_change(before: str, after: str) -> bool:

    combined = before + "\n" + after

    lines = [l.strip() for l in combined.splitlines() if l.strip()]

    if not lines:
        return True

    phpdoc_tokens = (
        "/**",
        "*/",
        "* @",
        "@param",
        "@return",
        "@var",
        "@throws",
    )

    for line in lines:

        if not any(t in line for t in phpdoc_tokens):
            return False

    return True


# -----------------------------
# MAIN
# -----------------------------
def build_function_diff_json(
    repo_path: str,
    old_ver: str,
    new_ver: str,
    only_ext: Optional[Set[str]] = None,
):

    id_counter = 1
    files = git_changed_files(repo_path, old_ver, new_ver)

    out = {
        "project": "phpmyadmin",
        "from_version": old_ver,
        "test_version": new_ver,
        "files": [],
    }

    for fp in files:

        if only_ext:
            ext = os.path.splitext(fp)[1].lower()
            if ext not in only_ext:
                continue

        diff_text = git_diff_file(repo_path, old_ver, new_ver, fp)

        if not diff_text.strip():
            continue

        touched = parse_touched_lines(diff_text)

        before_file = git_show_file(repo_path, old_ver, fp)
        after_file = git_show_file(repo_path, new_ver, fp)

        spans_old = extract_php_function_spans(before_file)
        spans_new = extract_php_function_spans(after_file)

        touched_funcs: Dict[str, Dict[str, str]] = {}

        global_new_lines = set()
        global_old_lines = set()

        for ln in touched.new_lines:

            sp = find_enclosing_span(spans_new, ln)

            if sp:
                touched_funcs.setdefault(sp.full_name, {})[
                    "after_span"
                ] = f"{sp.start_line}:{sp.end_line}"

            else:
                global_new_lines.add(ln)

        for ln in touched.old_lines:

            sp = find_enclosing_span(spans_old, ln)

            if sp:
                touched_funcs.setdefault(sp.full_name, {})[
                    "before_span"
                ] = f"{sp.start_line}:{sp.end_line}"

            else:
                global_old_lines.add(ln)

        file_entry = {"file_path": fp, "functions": []}

        for func_full_name, meta in touched_funcs.items():

            before_span = meta.get("before_span")
            after_span = meta.get("after_span")

            before_code = ""
            after_code = ""

            start = None
            end = None

            if before_span and before_file:
                a, b = before_span.split(":")
                a, b = int(a), int(b)
                before_code = slice_lines(before_file, a, b)
                start, end = a, b

            if after_span and after_file:
                a, b = after_span.split(":")
                a, b = int(a), int(b)
                after_code = slice_lines(after_file, a, b)

                # 🔥 after 기준으로 덮어쓰기 (더 중요)
                start, end = a, b

            file_entry["functions"].append(
                {
                    "id": id_counter,
                    "function": func_full_name,
                    "start": start,
                    "end": end,
                    "code_before_change": before_code,
                    "code_after_change": after_code,
                }
            )
            id_counter += 1

        if global_new_lines or global_old_lines:

            before_global = extract_global_snippet(before_file, global_old_lines)
            after_global = extract_global_snippet(after_file, global_new_lines)

            if not is_phpdoc_only_change(before_global, after_global):

                file_entry["functions"].append(
                    {
                        "id": id_counter,
                        "function": "<global>",
                        "code_before_change": before_global,
                        "code_after_change": after_global,
                    }
                )
            id_counter += 1

        if file_entry["functions"]:
            out["files"].append(file_entry)

    return out


# -----------------------------
# CLI
# -----------------------------
def main():

    ap = argparse.ArgumentParser()

    ap.add_argument("--repo", required=True)
    ap.add_argument("--old", required=True)
    ap.add_argument("--new", required=True)
    ap.add_argument("--out", default="diff_functions.json")

    args = ap.parse_args()

    save_full_diff(args.repo, args.old, args.new)
    # PHP only 자동 적용
    only_ext = {".php"}

    result = build_function_diff_json(
        repo_path=args.repo,
        old_ver=args.old,
        new_ver=args.new,
        only_ext=only_ext,
    )

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"[+] wrote {args.out}")


if __name__ == "__main__":
    main()