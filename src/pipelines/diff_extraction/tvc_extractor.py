import json


# -----------------------------
# 메인 로직
# -----------------------------
def extract_test_version_functions(json_path, output_path):

    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)

    for file in data["files"]:

        for fn in file["functions"]:

            # after_change 코드를 그대로 사용
            full_code = fn.get("code_after_change", "")

            fn["full_code"] = full_code

            # LLM scope 최소화
            fn.pop("code_before_change", None)
            fn.pop("code_after_change", None)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"[+] Extracted function code → {output_path}")


if __name__ == "__main__":

    extract_test_version_functions(
        json_path="diff_functions.json",
        output_path="llm_scope_functions.json",
    )