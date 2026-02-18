import subprocess

scripts = [
    ["php", "ast-extractor.php"],
    ["php", "event_routes_extractor.php"]
]

processes = [subprocess.Popen(cmd) for cmd in scripts]

for p in processes:
    p.wait()

print("All scripts finished.")
