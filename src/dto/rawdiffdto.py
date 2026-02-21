from pydantic import BaseModel, Field
from typing import List


class FunctionModifiedLinesDTO(BaseModel):
    added: List[str] = Field(default_factory=list)
    deleted: List[str] = Field(default_factory=list)


class RawDiffDTO(BaseModel):
    """Train 데이터 - 원본 취약점 정보"""

    cve_id: str
    code_before_change: str
    code_after_change: str
    patch: str

    function_modified_lines: FunctionModifiedLinesDTO

    cwe: List[str] = Field(default_factory=list)
    cve_description: str = ""

    id: int