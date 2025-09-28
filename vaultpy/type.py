from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def now_iso() -> str:
    """Helper to return the current UTC time in ISO format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class VaultEntry:
    label: str
    type: str  # e.g. "web", "ssh", "api", "wifi", "generic"
    username: Optional[str] = None
    password: Optional[str] = None
    url: Optional[str] = None
    token: Optional[str] = None
    private_key_path: Optional[str] = None
    passphrase: Optional[str] = None
    scopes: Optional[List[str]] = None
    notes: Optional[str] = None
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)

    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dict for JSON serialization, skipping None values."""
        return {k: v for k, v in asdict(self).items() if v is not None}

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "VaultEntry":
        """Create a VaultEntry from a dictionary."""
        return VaultEntry(**data)

    def update(self, **kwargs) -> None:
        """Update fields and refresh the updated_at timestamp."""
        for k, v in kwargs.items():
            if hasattr(self, k):
                setattr(self, k, v)
        self.updated_at = now_iso()
