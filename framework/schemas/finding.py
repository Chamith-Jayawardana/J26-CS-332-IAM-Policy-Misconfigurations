"""
Unified Finding Schema for Project J26-CS-332
Ensures all 4 components emit findings in an identical, machine-readable JSON structure.
"""

from dataclasses import dataclass, asdict
from typing import List, Optional
import json


@dataclass
class SecurityFinding:
    component_id: str         # e.g., 'iac_detection', 'storage_detection', 'iam_detection', 'network_detection'
    member_id: str            # e.g., 'IT23409378', 'IT23293458', 'IT23325296', 'IT23233430'
    repository: str           # Source repository name (e.g. 'terragoat')
    file_path: str            # Path to the misconfigured file
    line_range: List[int]     # [start_line, end_line]
    resource_id: str          # e.g., 'aws_s3_bucket.financial_records'
    predicted_smell: str      # Smell category from unified taxonomy
    confidence_score: float   # Between 0.0 and 1.0
    consensus_support: int    # Number of scanners that agreed (e.g. 2 or 3)
    is_advisory: bool = True  # Always advisory per requirement FR10
    schema_version: str = "v1.0"
    details: Optional[str] = None

    def to_dict(self):
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
