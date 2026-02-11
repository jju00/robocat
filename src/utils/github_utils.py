import os
import re
import requests
from typing import List, Dict, Any

# URLs를 찾기 위한 정규식
URL_REGEX = r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'

def flatten_to_strings(obj: Any) -> List[str]:
    """중첩된 dict/list 구조에서 모든 문자열 값을 재귀적으로 추출합니다."""
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, list):
        return [s for i in obj for s in flatten_to_strings(i)]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in flatten_to_strings(v)]
    return []

def normalize_references(advisory: Dict[str, Any]) -> List[str]:
    """advisory 객체에서 관련 GitHub URL 및 SHA를 추출하고 필터링합니다."""
    import json
    text_pool = json.dumps(advisory)
    
    # 1. 모든 GitHub URL 수집
    urls = re.findall(r'https?://github\.com/[\w\-\./]+', text_pool)
    
    # 2. Git SHA(40자 16진수)처럼 보이는 모든 항목 수집
    shas = re.findall(r'\b[a-f0-9]{40}\b', text_pool)
    
    relevant = []
    for url in set(urls):
        url = url.strip('"\' ,;).')
        if any(p in url for p in ["/commit/", "/pull/", "/compare/", "/issues/"]):
            relevant.append(url)
            
    # 해결을 돕기 위해 발견된 SHA에 대한 더미 커밋 링크 추가 (있는 경우)
    for sha in set(shas):
        # 나중에 식별할 수 있도록 SHA:prefix 형식으로 저장
        relevant.append(f"SHA:{sha}")
                
    return sorted(relevant)

class GitHubClient:
    def __init__(self, token: str = None):
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.headers = {
            "Accept": "application/vnd.github+json",
        }
        if self.token:
            self.headers["Authorization"] = f"token {self.token}"

    def fetch_repo_advisories(self, owner: str, repo: str) -> List[Dict[str, Any]]:
        """페이지네이션을 사용하여 특정 저장소의 모든 보안 공지(advisory)를 가져옵니다."""
        all_advisories = []
        page = 1
        per_page = 100
        seen_ids = set()
        while page < 10: # 안전을 위한 캡(Safety cap)
            print(f"    - Fetching repo advisories page {page}...")
            url = f"https://api.github.com/repos/{owner}/{repo}/security-advisories?per_page={per_page}&page={page}"
            try:
                response = requests.get(url, headers=self.headers)
                if response.status_code != 200:
                    print(f"Error fetching repo advisories (status {response.status_code}): {response.text}")
                    break
                data = response.json()
                if not data or not isinstance(data, list):
                    break
                
                # 중복을 제거하고 이 페이지의 모든 새로운 항목을 확인
                new_items = []
                for item in data:
                    ghsa_id = item.get('ghsa_id')
                    if ghsa_id not in seen_ids:
                        new_items.append(item)
                        seen_ids.add(ghsa_id)
                
                if not new_items:
                    print("    - No new advisories found on this page. Stopping.")
                    break
                    
                all_advisories.extend(new_items)
                print(f"    - Added {len(new_items)} new repo advisories.")
                
                if len(data) < per_page:
                    break
                page += 1
            except Exception as e:
                print(f"Exception fetching repo advisories (page {page}): {e}")
                break
        return all_advisories

    def search_advisories(self, query: str) -> List[Dict[str, Any]]:
        """대체 수단: Search API를 사용하여 보안 관련 이슈/PR을 검색합니다."""
        print(f"    - Fallback search for: {query}")
        all_results = []
        page = 1
        while page <= 2:
            print(f"    - Searching issues page {page}...")
            url = f"https://api.github.com/search/issues?q={query}&per_page=100&page={page}"
            try:
                response = requests.get(url, headers=self.headers)
                if response.status_code != 200:
                    print(f"Error searching issues (status {response.status_code}): {response.text}")
                    break
                data = response.json()
                items = data.get('items', [])
                if not items:
                    break
                for item in items:
                    all_results.append({
                        "ghsa_id": None,
                        "cve_id": None,
                        "html_url": item.get('html_url'),
                        "description": item.get('body', ''),
                        "references": [item.get('html_url')]
                    })
                print(f"    - Got {len(items)} items from search.")
                page += 1
            except Exception as e:
                print(f"Error searching issues (page {page}): {e}")
                break
        return all_results

    def get_full_advisory(self, ghsa_id: str) -> Dict[str, Any]:
        """글로벌 보안 공지에 대한 상세 정보를 가져옵니다."""
        url = f"https://api.github.com/advisories/{ghsa_id}"
        try:
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                return response.json()
        except: pass
        return {}

    def get_pr_info(self, owner: str, repo: str, pr_number: int) -> Dict[str, Any]:
        """merge_commit_sha를 가져오기 위해 특정 PR의 정보를 가져옵니다."""
        url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error fetching PR info: {e}")
            return {}

def get_reliable_advisories(client: GitHubClient, owner: str, repo: str) -> List[Dict[str, Any]]:
    """강력한 대체 로직을 포함한 보안 공지 수집 로직."""
    items = client.fetch_repo_advisories(owner, repo)
    
    # 항목이 0개이거나 참조 정보가 부족한 비율이 높을 경우 대체 검색 실행
    poor_ref_count = sum(1 for i in items if not normalize_references(i))
    item_count = len(items)
    
    if item_count == 0 or (poor_ref_count / max(item_count, 1)) > 0.4:
        print(f"Triggering fallback search for {owner}/{repo}...")
        fallback_items = client.search_advisories(f"{owner}/{repo}")
        # GHSA ID를 기준으로 병합 및 중복 제거
        seen_ids = {i.get('ghsa_id') for i in items if i.get('ghsa_id')}
        for f_item in fallback_items:
            if f_item.get('ghsa_id') not in seen_ids:
                items.append(f_item)
                seen_ids.add(f_item.get('ghsa_id'))
                
    return items
