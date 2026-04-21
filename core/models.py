from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime

@dataclass(frozen=True)
class ToolResult:
    target: str
    tool_name: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class Finding:
    tool_id: str
    data: Any
    description: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class Entity:
    value: str
    entity_type: str  # 'domain', 'ip', 'email'
    findings: Dict[str, Finding] = field(default_factory=dict)
    children: List['Entity'] = field(default_factory=list)

    def add_finding(self, tool_id: str, data: Any, description: str):
        self.findings[tool_id] = Finding(tool_id, data, description)
