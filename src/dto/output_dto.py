from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class TopVulnerabilityDTO:
    name: str
    reason: str
    supporting_cve_ids: List[str] = field(default_factory=list)
    representative_pattern: Optional[str] = None
    memory_corruption_category: Optional[str] = None
    cwe_ids: List[str] = field(default_factory=list)
    representative_code_examples: List[str] = field(default_factory=list)
    common_indicators: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RetrievalOutputDTO:
    id: int
    full_code: str
    top_vulnerabilities: List[TopVulnerabilityDTO] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "full_code": self.full_code,
            "top_vulnerabilities": [item.to_dict() for item in self.top_vulnerabilities],
        }
