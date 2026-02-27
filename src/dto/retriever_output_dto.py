from typing import List, Optional
from pydantic import BaseModel, Field

class VulnerabilityBehaviorDTO(BaseModel):
    vulnerability_cause_description: str
    trigger_condition: str
    specific_code_behavior_causing_vulnerability: str

class RetrievedKnowledgeDTO(BaseModel):
    cve_id: str = Field(..., description="CVE identifier, e.g. CVE-2013-7266")
    vulnerability_behavior: VulnerabilityBehaviorDTO
    solution_behavior: str
    # 외부 파일(LLM scope 요약 결과)을 통해 입력받는 필드
    purpose: Optional[str] = Field(None, description="Function purpose summary from scope analysis")
    function: Optional[str] = Field(None, description="Function name/signature from scope analysis")
