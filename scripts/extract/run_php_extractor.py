import subprocess
import sys
import os

# -----------------------------
# 인자 처리
# -----------------------------
args = sys.argv[1:]

if len(args) < 1:
    print("Usage: python run_extractors.py <target_dir> [output_dir]")
    sys.exit(1)

target_dir = args[0]
output_dir = args[1] if len(args) > 1 else "output"

# 출력 디렉터리 생성
os.makedirs(output_dir, exist_ok=True)

print(f"[+] Target Dir : {target_dir}")
print(f"[+] Output Dir : {output_dir}")

# -----------------------------
# 1️⃣ AST Extractor 실행 (output_dir 직접 전달)
# -----------------------------
ast_cmd = ["php", "ast-extractor.php", target_dir, output_dir]
print(f"\n[+] Running AST extractor: {' '.join(ast_cmd)}")

ast_process = subprocess.Popen(ast_cmd)

# -----------------------------
# 2️⃣ Event Routes Extractor 실행 (stdout → routes.json)
# -----------------------------
routes_output_file = os.path.join(output_dir, "routes.json")
print(f"[+] Running Routes extractor → {routes_output_file}")

with open(routes_output_file, "w") as f:
    routes_process = subprocess.Popen(
        ["php", "event_routes_extractor.php", target_dir],
        stdout=f,
        text=True
    )

# -----------------------------
# 프로세스 종료 대기
# -----------------------------
ast_process.wait()
routes_process.wait()

print("\n✔ All scripts finished.")
print(f"✔ AST + Routes saved in: {output_dir}")
