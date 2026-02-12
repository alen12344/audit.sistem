from __future__ import annotations
import re, hashlib
from dataclasses import dataclass
from typing import Any

@dataclass
class SuppressionRule:
    id: str
    reason: str
    title_regex: str | None = None
    location_regex: str | None = None
    cwe: str | None = None
    evidence_hash: str | None = None

    def matches(self, finding: dict[str, Any]) -> bool:
        if self.cwe and (str(finding.get("cwe","")).upper() != self.cwe.upper()):
            return False
        if self.title_regex and not re.search(self.title_regex, str(finding.get("title","")), re.I):
            return False
        if self.location_regex and not re.search(self.location_regex, str(finding.get("location","")), re.I):
            return False
        if self.evidence_hash:
            if hash_evidence(str(finding.get("evidence",""))) != self.evidence_hash:
                return False
        return True

def hash_evidence(evidence: str) -> str:
    return hashlib.sha256((evidence or "").encode("utf-8")).hexdigest()[:16]
