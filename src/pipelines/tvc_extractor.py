import json
import subprocess
import re
from typing import Optional


# -----------------------------
# Git helper
# -----------------------------
def git_show(repo_path: str, version: str, file_path: str) -> str:
    try:
        result = subprocess.run(
            ["git", "show", f"{version}:{file_path}"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
        return result.stdout
    except:
        return ""


# -----------------------------
# 함수 블록 추출
# -----------------------------
FUNC_PATTERN = r"""
^[ \t]*(?:(?:public|protected|private|static|final|abstract)\s+)*
function\s+&?\s*{name}\s*\(
"""


def extract_function_block(code: str, func_name: str) -> str:
    if not code or func_name == "<global>":
        return ""

    short_name = func_name.split("::")[-1]

    pattern = re.compile(
        FUNC_PATTERN.format(name=re.escape(short_name)),
        re.MULTILINE | re.VERBOSE,
    )

    m = pattern.search(code)
    if not m:
        return ""

    start = m.start()

    brace_pos = code.find("{", m.end())
    if brace_pos == -1:
        return ""

    depth = 0
    i = brace_pos

    while i < len(code):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return code[start:i+1]
        i += 1

    return ""


# -----------------------------
# 메인 로직
# -----------------------------
def extract_test_version_functions(repo_path, json_path, output_path):
    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)

    test_version = data["test_version"]

    for file in data["files"]:
        file_path = file["file_path"]
        code = git_show(repo_path, test_version, file_path)

        for fn in file["functions"]:
            func_name = fn["function"]
            full_code = extract_function_block(code, func_name)

            fn["full_code"] = full_code

            # 기존 before/after 제거 (LLM 스코프 최소화)
            fn.pop("code_before_change", None)
            fn.pop("code_after_change", None)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"[+] Extracted test-version function code → {output_path}")

if __name__ == "__main__":
    extract_test_version_functions(
        repo_path="/var/www/html/phpmyadmin",
        json_path="diff_functions.json",
        output_path="llm_scope_functions.json",
    )