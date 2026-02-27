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
    # unified=3 정도면 라인 매핑에 충분 (더 늘려도 됨)
    return run_git(repo_path, ["diff", f"-U{unified}", old_ver, new_ver, "--", file_path])


# -----------------------------
# Diff parsing: compute touched line numbers (new and old)
# -----------------------------
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass(frozen=True)
class TouchedLines:
    new_lines: Set[int]   # line numbers in new file that were added/modified
    old_lines: Set[int]   # line numbers in old file that were deleted/modified


def parse_touched_lines(diff_text: str) -> TouchedLines:
    """
    Parse unified diff into sets of touched line numbers:
    - new_lines: line numbers in new file that correspond to '+' lines
    - old_lines: line numbers in old file that correspond to '-' lines

    Context lines advance both counters but are not recorded.
    """
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

        # other metadata lines: ignore

    return TouchedLines(new_lines=new_lines, old_lines=old_lines)


# -----------------------------
# PHP function/method span extraction (robust-ish)
#   - We DO NOT use diff text to infer function name
#   - We parse the actual file and map touched line -> enclosing span
# -----------------------------
PHP_CLASS_RE = re.compile(r"^\s*(?:final\s+|abstract\s+)?class\s+([A-Za-z_]\w*)\b")
PHP_FUNCTION_RE = re.compile(
    r"""^\s*
        (?:(?:public|protected|private|static|final|abstract)\s+)*  # modifiers
        function\s+&?\s*([A-Za-z_]\w*)\s*\(                         # name(
    """,
    re.VERBOSE,
)

def strip_strings_rough(line: str) -> str:
    """
    Remove single/double-quoted strings roughly so we don't detect keywords inside strings.
    (Not a full lexer; just enough to reduce false positives.)
    """
    # remove escaped quotes minimally
    line = re.sub(r"'.*?(?<!\\)'", "''", line)
    line = re.sub(r'".*?(?<!\\)"', '""', line)
    return line


def count_braces_rough(line: str) -> Tuple[int, int]:
    s = strip_strings_rough(line)
    return s.count("{"), s.count("}")


@dataclass
class FunctionSpan:
    full_name: str        # e.g., "ClassName::method" or "func"
    short_name: str       # method/func name only
    start_line: int       # 1-based inclusive (function signature line)
    end_line: int         # 1-based inclusive (closing brace line)


def extract_php_function_spans(code: str) -> List[FunctionSpan]:
    """
    Extract function spans with class context.
    - Tracks class nesting by brace depth heuristics.
    - For each function, finds body '{' and matches braces to determine end.
    """
    if not code:
        return []

    lines = code.splitlines()
    spans: List[FunctionSpan] = []

    brace_depth = 0
    class_stack: List[Tuple[str, int]] = []  # (class_name, depth_before_class_open)
    pending_class: Optional[str] = None

    i = 0
    while i < len(lines):
        line = lines[i]
        line_no = i + 1

        # detect class line (outside strings)
        cm = PHP_CLASS_RE.match(strip_strings_rough(line))
        if cm:
            pending_class = cm.group(1)

        # count braces on this line (rough)
        opens, closes = count_braces_rough(line)

        # open class if pending_class and this line opens a block
        if pending_class and opens > 0:
            # assume first '{' after class starts the class scope
            class_stack.append((pending_class, brace_depth))
            pending_class = None

        current_class = class_stack[-1][0] if class_stack else None

        # detect function definition line
        fm = PHP_FUNCTION_RE.match(strip_strings_rough(line))
        if fm:
            fname = fm.group(1)
            func_sig_line = line_no
            func_class = current_class

            # find '{' that starts function body (may be on same or later lines)
            j = i
            found_body = False
            body_line = None
            body_pos_in_line = None

            while j < len(lines):
                s = strip_strings_rough(lines[j])
                pos = s.find("{")
                if pos != -1:
                    found_body = True
                    body_line = j + 1
                    body_pos_in_line = pos
                    break
                # stop if we hit ';' before a body: abstract/interface style
                if ";" in s and "{" not in s:
                    break
                j += 1

            if not found_body:
                # no body
                i += 1
                # update depth for this line before continue
                brace_depth += opens
                brace_depth -= closes
                # pop class if needed
                while class_stack and brace_depth <= class_stack[-1][1]:
                    class_stack.pop()
                continue

            # brace match from the function body opening brace
            # compute depth at the point just before consuming the function '{'
            # We'll scan characters from body_line onwards, but use line-level brace counts.
            depth_target = None

            # We scan starting at body_line-1
            k = body_line - 1
            # depth baseline: approximate current brace_depth at start of line k
            # We'll recompute baseline by simulating from start to k (costly), so instead:
            # do a local brace scan from k onward with an independent counter initialized at 0.
            func_depth = 0
            started = False
            end_line = body_line

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
                                k = len(lines)  # break outer
                                break
                if k < len(lines):
                    end_line = k + 1
                k += 1

            full_name = f"{func_class}::{fname}" if func_class else fname
            spans.append(FunctionSpan(full_name=full_name, short_name=fname, start_line=func_sig_line, end_line=end_line))

            # continue normally (do not jump i to end_line; keep scanning)
            # because there may be nested function definitions (rare) or multiple in a file.
            # We'll keep i moving linearly.

        # update brace depth for file-level class tracking
        brace_depth += opens
        brace_depth -= closes
        if brace_depth < 0:
            brace_depth = 0

        # pop class scopes when leaving
        while class_stack and brace_depth <= class_stack[-1][1]:
            class_stack.pop()

        i += 1

    return spans


def find_enclosing_span(spans: List[FunctionSpan], line_no: int) -> Optional[FunctionSpan]:
    for sp in spans:
        if sp.start_line <= line_no <= sp.end_line:
            return sp
    return None


def slice_lines(code: str, start_line: int, end_line: int) -> str:
    lines = code.splitlines()
    s = max(0, start_line - 1)
    e = min(len(lines), end_line)
    return ("\n".join(lines[s:e]).rstrip() + "\n") if s < e else ""


def extract_global_snippet(code: str, touched_lines: Set[int], context: int = 25) -> str:
    """
    Extract a compact snippet around touched lines (for <global> changes).
    Merge nearby ranges.
    """
    if not code or not touched_lines:
        return ""

    lines = code.splitlines()
    n = len(lines)

    # build ranges [l-context, l+context]
    ranges = []
    for l in sorted(touched_lines):
        a = max(1, l - context)
        b = min(n, l + context)
        ranges.append((a, b))

    # merge overlapping ranges
    merged = []
    for a, b in ranges:
        if not merged or a > merged[-1][1] + 1:
            merged.append([a, b])
        else:
            merged[-1][1] = max(merged[-1][1], b)

    chunks = []
    for a, b in merged:
        chunk = "\n".join(lines[a-1:b]).rstrip()
        chunks.append(f"/* lines {a}-{b} */\n{chunk}\n")

    return "\n".join(chunks).rstrip() + "\n"


# -----------------------------
# Main build logic
# -----------------------------
def build_function_diff_json(
    repo_path: str,
    old_ver: str,
    new_ver: str,
    only_ext: Optional[Set[str]] = None,
    unified: int = 3,
    global_context: int = 25,
) -> Dict:
    files = git_changed_files(repo_path, old_ver, new_ver)

    out = {
        "project": "phpmyadmin",
        "from_version": old_ver,
        "test_version": new_ver,
        "files": []
    }

    for fp in files:
        if only_ext:
            ext = os.path.splitext(fp)[1].lower()
            if ext not in only_ext:
                continue

        diff_text = git_diff_file(repo_path, old_ver, new_ver, fp, unified=unified)
        if not diff_text.strip():
            continue

        touched = parse_touched_lines(diff_text)

        before_file = git_show_file(repo_path, old_ver, fp)
        after_file = git_show_file(repo_path, new_ver, fp)

        spans_old = extract_php_function_spans(before_file) if before_file else []
        spans_new = extract_php_function_spans(after_file) if after_file else []

        # touched functions keyed by full_name
        touched_funcs: Dict[str, Dict[str, str]] = {}

        # 1) Map new touched lines to new spans => after_code
        global_new_lines: Set[int] = set()
        for ln in touched.new_lines:
            sp = find_enclosing_span(spans_new, ln)
            if sp:
                touched_funcs.setdefault(sp.full_name, {})["after_span"] = f"{sp.start_line}:{sp.end_line}"
            else:
                global_new_lines.add(ln)

        # 2) Map old touched lines to old spans => before_code (captures deletions-only too)
        global_old_lines: Set[int] = set()
        for ln in touched.old_lines:
            sp = find_enclosing_span(spans_old, ln)
            if sp:
                touched_funcs.setdefault(sp.full_name, {})["before_span"] = f"{sp.start_line}:{sp.end_line}"
            else:
                global_old_lines.add(ln)

        file_entry = {"file_path": fp, "functions": []}

        # 3) Emit function entries
        for func_full_name, meta in sorted(touched_funcs.items(), key=lambda x: x[0]):
            before_span = meta.get("before_span")
            after_span = meta.get("after_span")

            before_code = ""
            after_code = ""

            if before_span and before_file:
                a, b = before_span.split(":")
                before_code = slice_lines(before_file, int(a), int(b))

            if after_span and after_file:
                a, b = after_span.split(":")
                after_code = slice_lines(after_file, int(a), int(b))

            file_entry["functions"].append({
                "function": func_full_name,
                "code_before_change": before_code,
                "code_after_change": after_code,
            })

        # 4) Handle global changes with snippets (prevents loss)
        if global_new_lines or global_old_lines:
            before_global = extract_global_snippet(before_file, global_old_lines, context=global_context) if before_file else ""
            after_global = extract_global_snippet(after_file, global_new_lines, context=global_context) if after_file else ""
            file_entry["functions"].append({
                "function": "<global>",
                "code_before_change": before_global,
                "code_after_change": after_global,
            })

        # only add if there is something
        if file_entry["functions"]:
            out["files"].append(file_entry)

    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="repo path, e.g., /var/www/html/phpmyadmin")
    ap.add_argument("--old", required=True, help="old version tag/branch")
    ap.add_argument("--new", required=True, help="new version tag/branch")
    ap.add_argument("--out", default="diff_functions.json", help="output json path")
    ap.add_argument("--php-only", action="store_true", help="only process .php files")
    ap.add_argument("--unified", type=int, default=3, help="git diff unified context lines")
    ap.add_argument("--global-context", type=int, default=25, help="context lines for <global> snippet")
    args = ap.parse_args()

    only_ext = {".php"} if args.php_only else None

    out_json = build_function_diff_json(
        repo_path=args.repo,
        old_ver=args.old,
        new_ver=args.new,
        only_ext=only_ext,
        unified=args.unified,
        global_context=args.global_context,
    )

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out_json, f, ensure_ascii=False, indent=2)

    print(f"[+] Wrote: {args.out} (files: {len(out_json['files'])})")


if __name__ == "__main__":
    main()