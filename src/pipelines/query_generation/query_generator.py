import re
import json
from typing import List, Optional

from ...dto.rawdiffdto import RawDiffDTO
from ...dto.query_dto import StructuredQueryDTO
from ...utils.llm_client import OpenAIClient

class QueryGenerator:
    """
    Diff 정보(RawDiffDTO)를 기반으로 정규화된 검색 쿼리(StructuredQueryDTO)를 생성하는 엔진.
    """
    def __init__(self, llm_client: OpenAIClient):
        self.llm_client = llm_client

    def _extract_functions_heuristic(self, code: str) -> List[str]:
        """
        정규식을 사용하여 코드에서 함수 이름을 대략적으로 추출 (PHP/Python/C 스타일)
        """
        functions = []
        # Pattern: function name(...) or def name(...)
        # PHP: function foo()
        # Python: def foo():
        # C: void foo() - hard to regex perfectly, but trying simple pattern
        patterns = [
            r"function\s+([a-zA-Z0-9_]+)\s*\(", # PHP/JS
            r"def\s+([a-zA-Z0-9_]+)\s*\(",      # Python
            r"\b([a-zA-Z0-9_]+)\s*\(.*\)\s*\{"  # C-like (simplified)
        ]
        
        for p in patterns:
            matches = re.findall(p, code)
            functions.extend(matches)
            
        return list(set(functions))

    def _generate_semantic_query_prompt(self, raw: RawDiffDTO) -> str:
        return f"""
Analyze the following code patch/diff to identify the vulnerability it fixes.
CVE ID: {raw.cve_id}
Description: {raw.cve_description}

Code Before Change:
'''
{raw.code_before_change[:1000]}...
'''

Code After Change (Patch):
'''
{raw.code_after_change[:1000]}...
'''

Based on this, please provide:
1. "keywords": A list of technical keywords relevant to this vulnerability (e.g., "buffer overflow", "memcpy", "XSS").
2. "queries": A list of natural language search queries that a security researcher might use to find similar vulnerabilities or this specific fix (e.g., "Fix for SQL injection in login function").

Output JSON format only:
{{
  "keywords": ["..."],
  "queries": ["..."]
}}
""".strip()

    def generate(self, raw: RawDiffDTO) -> StructuredQueryDTO:
        """
        RawDiffDTO -> StructuredQueryDTO 변환 메인 로직
        """
        # 1. Heuristic Extraction
        # 변경 전 코드를 기준으로 함수 이름 추출 (변경된 함수 추정)
        # 더 정확하게 하려면 modified_lines와 매핑해야 하지만, 여기선 전체 코드에서 함수 추출
        functions = self._extract_functions_heuristic(raw.code_before_change)
        
        # 메타데이터 추론 (파일 확장자 등은 RawDiffDTO에 path가 없으면 추론 어려움, 일단 생략 or content 기반 추론)
        extensions = []
        if "<?php" in raw.code_before_change:
            extensions.append("php")
        elif "def " in raw.code_before_change:
            extensions.append("py")

        # 2. LLM Semantic Extraction
        keywords = []
        queries = []
        
        if raw.code_before_change and raw.code_after_change:
            prompt = self._generate_semantic_query_prompt(raw)
            try:
                # LLM 호출
                from src.utils import llm_client as llm
                messages = llm.generate_simple_prompt(prompt)
                response_text = self.llm_client.generate_text(messages)
                # JSON 파싱 시도
                if "{" in response_text:
                    start = response_text.find("{")
                    end = response_text.rfind("}") + 1
                    data = json.loads(response_text[start:end])
                    keywords = data.get("keywords", [])
                    queries = data.get("queries", [])
            except Exception as e:
                print(f"[QueryGenerator] LLM extraction failed: {e}")

        # 3. DTO 생성
        return StructuredQueryDTO(
            target_functions=functions,
            related_files=[raw.file_path] if raw.file_path else [],
            file_extensions=extensions,
            keywords=keywords,
            natural_language_queries=queries,
            commit_hash=raw.commit_hash,
            project_name=None
        )
