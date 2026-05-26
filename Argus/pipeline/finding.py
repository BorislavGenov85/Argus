"""
Finding — unified output record from any module.

Every piece of actionable recon data becomes a Finding. This makes
filtering, reporting, exporting, and searching trivial regardless
of which module produced the data.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class FindingType(str, enum.Enum):
    PORT = 'port'
    DIRECTORY = 'directory'
    DOMAIN = 'domain'
    VHOST = 'vhost'
    DNS_RECORD = 'dns_record'
    TECHNOLOGY = 'technology'
    CREDENTIAL = 'credential'
    MISCONFIGURATION = 'misconfiguration'


class Severity(str, enum.Enum):
    INFO = 'info'
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'


@dataclass
class Finding:
    type: FindingType
    source: str              # module name that produced it
    severity: Severity = Severity.INFO
    data: dict[str, Any] = field(default_factory=dict)
    description: str = ''
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            'type': self.type.value,
            'source': self.source,
            'severity': self.severity.value,
            'data': self.data,
            'description': self.description,
            'timestamp': self.timestamp.isoformat(),
        }
