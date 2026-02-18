import subprocess
import sys

# Python 실행 시 전달된 인자들
args = sys.argv[1:]  # 스크립트 이름 제외

if not args:
    print("Usage: python run_extractors.py <target_dir> [output_dir]")
    sys.exit(1)

scripts = [
    ["php", "ast-extractor.php", *args],
    ["php", "event_routes_extractor.php", *args]
]

processes = [subprocess.Popen(cmd) for cmd in scripts]

for p in processes:
    p.wait()

print("All scripts finished.")

