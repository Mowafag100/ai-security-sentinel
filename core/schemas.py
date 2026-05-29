from pydantic import BaseModel, Field
from typing import List, Optional

class VulnerabilityDetail(BaseModel):
    cwe_id: str = Field(description="The CWE ID of the vulnerability (e.g., CWE-89)")
    severity: str = Field(description="Severity level: LOW, MEDIUM, HIGH, CRITICAL")
    line_number: Optional[int] = Field(None, description="Line number where the issue resides")
    description: str = Field(description="Detailed explanation of the security issue")
    remediation: str = Field(description="Secure code snippet or fix recommendation")

class AuditReportSchema(BaseModel):
    status: str = Field(description="Success or fallback status")
    vulnerabilities_found: int = Field(description="Total count of issues identified")
    issues: List[VulnerabilityDetail] = Field(default=[], description="List of discovered vulnerabilities")
