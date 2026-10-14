"""Data models and schemas for IncidentIQ."""

from dataclasses import dataclass, field, asdict
from enum import Enum
import json
from typing import List, Dict, Any
from datetime import datetime


class SeverityLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class IncidentCategory(str, Enum):
    DATABASE = "Database & Persistence"
    INFRASTRUCTURE = "Infrastructure & Compute"
    NETWORKING = "Networking & DNS"
    SECURITY = "Security & Access"
    DEPLOYMENT = "Deployment & Release"
    THIRD_PARTY = "Third-Party Integration"
    STORAGE = "Storage & IO"
    GENERAL = "General Application"


@dataclass
class IncidentAnalysis:
    incident_id: str
    timestamp: str
    title: str
    severity: SeverityLevel
    category: IncidentCategory
    confidence_score: int
    summary: str
    likely_root_cause: str
    supporting_evidence: List[str] = field(default_factory=list)
    prioritized_troubleshooting_steps: List[str] = field(default_factory=list)
    recommended_next_action: str = ""
    blast_radius: str = "Unknown"
    raw_input: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert the analysis to a serializable dictionary."""
        data = asdict(self)
        data["severity"] = self.severity.value
        data["category"] = self.category.value
        return data

    def to_json(self, indent: int = 2) -> str:
        """Export analysis to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)
