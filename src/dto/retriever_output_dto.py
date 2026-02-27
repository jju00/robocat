from typing import List
from pydantic import BaseModel, Field

class VulnerabilityBehaviorDTO(BaseModel):
    vulnerability_cause_description: str
    trigger_condition: str
    specific_code_behavior_causing_vulnerability: str

class RetrievedKnowledgeDTO(BaseModel):
    cve_id: str = Field(..., description="CVE identifier, e.g. CVE-2013-7266")
    vulnerability_behavior: VulnerabilityBehaviorDTO
    solution_behavior: str