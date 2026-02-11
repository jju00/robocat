import re
from typing import List, Dict, Any, Tuple

def parse_hunks(git_show_output: str) -> List[Dict[str, Any]]:
    """`git show -U0` 결과에서 hunk 헤더와 라인 정보를 추출하여 파싱합니다."""
    hunks = []
    # 더 강력한 hunk 헤더 정규식:
    # @@ -1,2 +3,4 @@ 및 @@ -1 +3 @@ 형식을 모두 처리합니다.
    # 뒤에 오는 내용도 허용합니다.
    hunk_pattern = re.compile(r'^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@')
    
    current_hunk = None
    lines = git_show_output.splitlines()
    
    for line in lines:
        match = hunk_pattern.match(line)
        if match:
            if current_hunk:
                hunks.append(current_hunk)
            
            # 그룹 2는 after_start_line (수정 후 시작 라인)입니다.
            after_start = int(match.group(2))
            current_hunk = {
                "after_start_line": after_start,
                "added": 0,
                "deleted": 0,
                "content": []
            }
        elif current_hunk:
            if line.startswith('+++') or line.startswith('---'):
                continue
            if line.startswith('+'):
                current_hunk["added"] += 1
                current_hunk["content"].append(line)
            elif line.startswith('-'):
                current_hunk["deleted"] += 1
                current_hunk["content"].append(line)
                
    if current_hunk:
        hunks.append(current_hunk)
        
    return hunks

def security_keyword_score(text: str) -> int:
    """보안 관련성을 판단하기 위한 간단한 키워드 기반 점수 계산 방식."""
    keywords = {
        "fix": 10, "security": 10, "cve": 10, "ghsa": 10,
        "escape": 5, "sanitize": 5, "validate": 5, "vuln": 5,
        "xss": 5, "injection": 5, "bypass": 5
    }
    score = 0
    text_lower = text.lower()
    for kw, val in keywords.items():
        if kw in text_lower:
            score += val
    return score

def ext_priority(path: str) -> int:
    """파일 확장자에 따른 우선순위를 반환합니다 (낮을수록 좋음)."""
    if path.endswith('.php'): return 1
    if path.endswith('.twig'): return 2
    if path.endswith('.js'): return 3
    return 99

def is_noise_only(commit_info: Dict[str, Any]) -> bool:
    """커밋이 노이즈 파일(문서, 설정 등)만 수정하는지 확인합니다."""
    noise_patterns = [
        r'\.md$', r'\.yml$', r'\.yaml$', r'composer\.lock$', 
        r'package-lock\.json$', r'\.gitignore$', r'\.github/'
    ]
    paths = commit_info.get('paths', [])
    if not paths: return False
    
    for path in paths:
        is_current_noise = any(re.search(p, path) for p in noise_patterns)
        if not is_current_noise:
            return False # 적어도 하나의 노이즈가 아닌 파일을 찾음
    return True

def pick_best_file(files: List[Dict[str, Any]], exclude_patterns: List[str]) -> Dict[str, Any]:
    """간소화된 점수 계산 방식을 사용하여 가장 대표적인 파일을 선택합니다."""
    candidates = []
    for f in files:
        path = f['path']
        if any(re.search(p, path) for p in exclude_patterns):
            continue
        candidates.append(f)
        
    if not candidates:
        return None
        
    # 정렬: 확장자 우선순위(1 > 2 > 3), 그 다음 변경 횟수(최대 500까지, 클수록 좋음)
    # 두 번째 정렬 키에서 내림차순을 위해 음수(-) 변경 횟수 사용
    candidates.sort(key=lambda x: (
        ext_priority(x['path']), 
        -min(x.get('changes', 0), 500)
    ))
    
    return candidates[0]
