from typing import List, Tuple, Optional

def extract_php_function(content: str, line_num: int) -> Optional[str]:
    """
    line_num을 포함하는 완전한 PHP 함수/메서드 블록 추출을 시도합니다.
    기본적인 중괄호 카운팅과 정규표현식을 사용하여 이를 감지합니다.
    """
    lines = content.splitlines()
    if line_num > len(lines):
        return None
    
    # 1. 함수/메서드 시작점을 찾기 위해 위로 검색
    start_idx = -1
    for i in range(line_num - 1, -1, -1):
        if 'function' in lines[i]:
            start_idx = i
            break
            
    if start_idx == -1:
        return None
        
    # 2. 블록의 끝을 찾기 위한 중괄호 카운팅
    brace_count = 0
    found_start = False
    extracted_lines = []
    
    for i in range(start_idx, len(lines)):
        line = lines[i]
        extracted_lines.append(line)
        brace_count += line.count('{')
        brace_count -= line.count('}')
        
        if '{' in line:
            found_start = True
            
        if found_start and brace_count == 0:
            return "\n".join(extracted_lines)
            
    return None

def get_context_window(content: str, line_num: int, window_size: int = 80) -> str:
    """line_num 주변의 고정된 줄 수(window_size)만큼 추출합니다."""
    lines = content.splitlines()
    start = max(0, line_num - 1 - window_size)
    end = min(len(lines), line_num + window_size)
    return "\n".join(lines[start:end])

def extract_with_validation(
    content: str, 
    line_num: int, 
    patch_signatures: List[str], 
    is_php: bool = True,
    window_size: int = 80
) -> Tuple[str, str]:
    """
    시그니처 검증을 포함한 2단계 추출 로직입니다.
    (추출된 코드, 모드)를 반환합니다.
    """
    # 1단계: PHP 구조적 추출 (가능한 경우)
    if is_php:
        code = extract_php_function(content, line_num)
        if code and validate_signatures(code, patch_signatures):
            return code, "function"
            
    # 2단계: 윈도우 기반 대체 추출
    code = get_context_window(content, line_num, window_size)
    if validate_signatures(code, patch_signatures):
        return code, "context"
        
    # 검증 실패 시 호출자가 더 큰 윈도우로 재시도하거나 에러를 처리합니다.
    return code, "failed_validation"

def validate_signatures(code: str, signatures: List[str]) -> bool:
    """추출된 코드에 적어도 하나의 시그니처가 포함되어 있는지 확인합니다 (공백 무시)."""
    if not signatures: 
        return True
    
    import re
    def normalize(t): return re.sub(r'\s+', '', t)
    
    norm_code = normalize(code)
    for sig in signatures:
        if normalize(sig) in norm_code:
            return True
    return False

def extract_signatures_from_patch(patch: str) -> List[str]:
    """패치의 '+' 라인에서 1~3개의 강력한 시그니처 라인을 추출합니다."""
    signatures = []
    for line in patch.splitlines():
        if line.startswith('+') and not line.startswith('+++'):
            clean = line[1:].strip()
            if len(clean) > 8: # 너무 짧은 시그니처는 피함
                signatures.append(clean)
                if len(signatures) >= 3: # 작은 세트 유지
                    break
    return signatures
