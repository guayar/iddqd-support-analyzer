"""Knowledge Base data models.

Defines Article, Case, Tag, and relationship structures.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, List
import json


@dataclass
class Article:
    """Knowledge Base Article - reusable troubleshooting knowledge."""

    id: str
    title: str
    content: str  # Markdown
    summary: Optional[str] = None
    status: str = "active"  # active, archived, deprecated
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    finding_codes: List[str] = field(default_factory=list)  # JWT_KID_NOT_FOUND, etc
    related_article_ids: List[str] = field(default_factory=list)
    display_id_seq: int = 0  # Sequential ID for display

    @property
    def display_id(self) -> str:
        """Return friendly sequential display ID (AN00000001 format)."""
        return f"AN{self.display_id_seq:08d}"

    def to_dict(self):
        """Convert to dict, handling datetime serialization."""
        d = asdict(self)
        if self.created_at:
            d["created_at"] = self.created_at.isoformat()
        if self.updated_at:
            d["updated_at"] = self.updated_at.isoformat()
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Article":
        """Create from dict, parsing ISO datetime strings."""
        data = data.copy()
        if isinstance(data.get("created_at"), str):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        if isinstance(data.get("updated_at"), str):
            data["updated_at"] = datetime.fromisoformat(data["updated_at"])
        return cls(**data)


@dataclass
class Case:
    """Knowledge Base Case - individual troubleshooting investigation."""

    id: str
    title: str
    content: str  # Markdown
    summary: Optional[str] = None
    analyze_snapshot: Optional[str] = None  # JSON string of findings
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    related_article_ids: List[str] = field(default_factory=list)
    display_id_seq: int = 0  # Sequential ID for display

    @property
    def display_id(self) -> str:
        """Return friendly sequential display ID (CN00000001 format)."""
        return f"CN{self.display_id_seq:08d}"

    def to_dict(self):
        """Convert to dict."""
        d = asdict(self)
        if self.created_at:
            d["created_at"] = self.created_at.isoformat()
        if self.updated_at:
            d["updated_at"] = self.updated_at.isoformat()
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Case":
        """Create from dict."""
        data = data.copy()
        if isinstance(data.get("created_at"), str):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        if isinstance(data.get("updated_at"), str):
            data["updated_at"] = datetime.fromisoformat(data["updated_at"])
        return cls(**data)


@dataclass
class Tag:
    """Knowledge Base Tag."""

    id: str
    name: str


@dataclass
class FindingLink:
    """Link between finding code and Article."""

    id: str
    article_id: str
    finding_code: str  # JWT_KID_NOT_FOUND
    created_at: Optional[datetime] = None

    def to_dict(self):
        d = asdict(self)
        if self.created_at:
            d["created_at"] = self.created_at.isoformat()
        return d


@dataclass
class Revision:
    """Article/Case revision history."""

    id: str
    article_id: Optional[str] = None
    case_id: Optional[str] = None
    content: str = ""
    version: int = 1
    created_at: Optional[datetime] = None
    created_by: Optional[str] = None
    change_note: Optional[str] = None

    def to_dict(self):
        d = asdict(self)
        if self.created_at:
            d["created_at"] = self.created_at.isoformat()
        return d
