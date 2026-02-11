import os
import re
import json
import argparse
import sys
from pathlib import Path
from typing import List, Dict, Any

# 프로젝트 루트를 시스템 경로에 추가
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.utils import github_utils, git_utils, scoring_utils, extraction_utils

# 상수 설정
OWNER = "getgrav"
REPO = "grav"
REPO_URL = f"https://github.com/{OWNER}/{REPO}.git"
LOCAL_REPO_PATH = "tmp/grav_repo"
DATA_DIR = Path("data/train")
STATE_FILE = Path("data/state_registry.json")
EXCLUDE_PATTERNS = [
    r'tests/', r'docs/', r'bin/', r'\.md$', r'\.yml$', r'\.yaml$', 
    r'composer\.lock$', r'package-lock\.json$', r'\.gitignore$', r'\.github/'
]

def load_state() -> Dict[str, str]:
    if STATE_FILE.exists():
        with open(STATE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_state(state: Dict[str, str]):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, 'w', encoding='utf-8') as f:
        json.dump(state, f, indent=4)

# GitService 인스턴스 캐시
GIT_SERVICES = {}

def get_git_service(repo_full_name: str) -> git_utils.GitService:
    if repo_full_name in GIT_SERVICES:
        return GIT_SERVICES[repo_full_name]
    
    repo_url = f"https://github.com/{repo_full_name}.git"
    # Windows의 CWD 문제를 피하기 위해 local_path에 절대 경로를 사용합니다.
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    local_path = os.path.join(base_dir, "tmp", repo_full_name.replace("/", "_"))
    
    print(f"  Setting up GitService for {repo_full_name} at {local_path}...")
    svc = git_utils.GitService(repo_url, local_path)
    GIT_SERVICES[repo_full_name] = svc
    return svc

def process_cve(advisory: Dict[str, Any], gh_client: github_utils.GitHubClient):
    ghsa_id = advisory.get('ghsa_id')
    cve_id = advisory.get('cve_id') or ghsa_id
    print(f"\n>>> Processing {cve_id} ({ghsa_id})")
    
    # 1. 수정 커밋 및 저장소 확인
    sha = None
    target_repo = None
    refs = github_utils.normalize_references(advisory)
    
    # 보안 공지에서 언급된 모든 저장소 추적
    potential_repos = set([f"{OWNER}/{REPO}"])
    
    # 우선순위 1: 저장소와 SHA 정보가 포함된 직접적인 커밋 링크
    for r in refs:
        commit_match = re.search(r'github\.com/([^/]+/[^/]+)/commit/([a-f0-9]+)', r, re.I)
        if commit_match:
            target_repo = commit_match.group(1)
            sha = commit_match.group(2)
            print(f"  Found direct commit: {sha} in {target_repo}")
            break
            
    # 우선순위 2: PR 링크
    if not sha:
        for r in refs:
            pr_match = re.search(r'github\.com/([^/]+/[^/]+)/pull/(\d+)', r, re.I)
            if pr_match:
                repo_name = pr_match.group(1)
                potential_repos.add(repo_name)
                pr_num = int(pr_match.group(2))
                try:
                    owner_name, r_name = repo_name.split('/')
                    pr_info = gh_client.get_pr_info(owner_name, r_name, pr_num)
                    sha = pr_info.get('merge_commit_sha') or pr_info.get('head', {}).get('sha')
                    if sha:
                        target_repo = repo_name
                        print(f"  Resolved PR #{pr_num} in {target_repo} to SHA: {sha}")
                        break
                except: continue

    # 우선순위 3: 보안 공지 텍스트에서 발견된 일반 SHA
    if not sha:
        bare_shas = [r.split("SHA:")[-1] for r in refs if r.startswith("SHA:")]
        if bare_shas:
            # 이 SHA가 잠재적인 저장소들 중 하나에 존재하는지 확인 시도
            for r_name in potential_repos:
                try:
                    svc = get_git_service(r_name)
                    # SHA 존재 여부 확인을 위해 git show 사용
                    svc.run_command(["show", "--quiet", bare_shas[0]])
                    sha = bare_shas[0]
                    target_repo = r_name
                    print(f"  Found valid bare SHA {sha} in {target_repo}")
                    break
                except: continue

    if not (sha and target_repo):
        print(f"  (!) No fixing commit found for {cve_id}. Skipping.")
        return "MISSING_COMMIT"

    # 2. 대상 저장소를 위한 Git 서비스 설정
    try:
        git_svc = get_git_service(target_repo)
        files = git_svc.get_modified_files_info(sha)
        best_file = scoring_utils.pick_best_file(files, EXCLUDE_PATTERNS)
        if not best_file:
            print(f"  (!) No suitable file found in {target_repo} @ {sha}. Skipping.")
            return "NO_SUITABLE_FILE"
        
        file_path = best_file['path']
        print(f"  Selected file: {file_path} from {target_repo}")

        # 3. Hunk 및 라인 선택
        show_output = git_svc.get_show_output(sha, file_path)
        if not show_output:
            print(f"  (!) GIT_SHOW_FAIL for {file_path} in {target_repo}.")
            return "GIT_SHOW_FAIL"
            
        hunks = scoring_utils.parse_hunks(show_output)
        if not hunks:
            print(f"  (!) HUNK_PARSE_FAIL for {file_path} in {target_repo}.")
            return "HUNK_PARSE_FAIL"
            
        best_hunk = max(hunks, key=lambda h: h['added'] + h['deleted'])
        line_num = best_hunk['after_start_line']
        
        # 4. 추출 및 검증
        patch_signatures = extraction_utils.extract_signatures_from_patch(show_output)
        is_php = file_path.endswith('.php')
        
        after_content = git_svc.get_file_content(sha, file_path)
        extracted_after, mode = extraction_utils.extract_with_validation(
            after_content, line_num, patch_signatures, is_php=is_php, window_size=80
        )
        
        if mode == "failed_validation":
            print("  Retrying with window 120...")
            extracted_after, mode = extraction_utils.extract_with_validation(
                after_content, line_num, patch_signatures, is_php=is_php, window_size=120
            )

        if mode == "failed_validation":
            return "VAL_FAIL"

        before_content = git_svc.get_file_content(f"{sha}^", file_path)
        extracted_before, _ = extraction_utils.extract_with_validation(
            before_content, line_num, [], is_php=is_php, window_size=80 if mode == "function" else 80
        )

        # 5. 저장
        output_item = {
            "cve_id": cve_id,
            "code_before_change": extracted_before,
            "code_after_change": extracted_after,
            "patch": show_output,
            "function_modified_lines": {
                "added": [l[1:] for l in show_output.splitlines() if l.startswith('+') and not l.startswith('+++')],
                "deleted": [l[1:] for l in show_output.splitlines() if l.startswith('-') and not l.startswith('---')]
            },
            "file_path": file_path,
            "commit_hash": sha,
            "repository": target_repo,
            "cwe": [v.get('cwe_id') for v in advisory.get('vulnerabilities', []) if v.get('cwe_id')] or advisory.get('cwe_ids', []),
            "cve_description": advisory.get('description', ''),
            "id": len(os.listdir(DATA_DIR)) + 1 if DATA_DIR.exists() else 1,
            "extraction_mode": mode
        }
        
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        out_path = DATA_DIR / f"{cve_id}.json"
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump([output_item], f, indent=4, ensure_ascii=False)
            
        print(f"  [SUCCESS] Saved {cve_id} in {target_repo}")
        return "COMPLETED"

    except Exception as e:
        print(f"  [ERROR] {str(e)}")
        return f"ERROR: {str(e)}"

def main():
    parser = argparse.ArgumentParser(description="Collect Grav Security Advisories and extract patches.")
    parser.add_argument("--token", type=str, help="GitHub Personal Access Token")
    args = parser.parse_args()

    gh_client = github_utils.GitHubClient(token=args.token)
    git_svc = git_utils.GitService(REPO_URL, LOCAL_REPO_PATH)
    
    state = load_state()
    
    print("Collecting advisories...")
    advisories = github_utils.get_reliable_advisories(gh_client, OWNER, REPO)
    print(f"Found {len(advisories)} advisories.")
    
    for adv in advisories:
        # 식별자(ID) 확인
        ghsa_id = adv.get('ghsa_id')
        html_url = adv.get('html_url', '')
        
        # 검색 결과인 경우 (ghsa_id 없음), ID를 추출할 수 있다면 상세 GHSA 정보를 가져옵니다.
        if not ghsa_id:
            if "GHSA-" in html_url:
                ghsa_id = html_url.split("GHSA-")[-1].split('/')[0]
                full_adv = gh_client.get_full_advisory(ghsa_id)
                if full_adv:
                    adv = full_adv
                    ghsa_id = adv.get('ghsa_id')
        
        # 여전히 ID가 없는 경우, 'null' 키가 생성되는 것을 방지하기 위해 html_url을 대체 식별자로 사용합니다.
        identifier = ghsa_id or html_url or "unknown"
        
        # if identifier in state and state[identifier] == "COMPLETED":
        # ...
            
        status = process_cve(adv, gh_client)
        state[identifier] = status
        save_state(state)

if __name__ == "__main__":
    main()
