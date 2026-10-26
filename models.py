from dataclasses import dataclass, field
from typing import Optional

@dataclass
class Finding:
    kind: str
    url: str
    param: str = ""
    payload: str = ""
    evidence: str = ""
    severity: str = "info"
    risk: str = ""
    cvss: Optional[float] = None
    exploits: list = field(default_factory=list)
    exploited: bool = False
    detail: dict = field(default_factory=dict)

@dataclass
class Report:
    target: str
    findings: list = field(default_factory=list)
    open_ports: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    subdomains: dict = field(default_factory=dict)
