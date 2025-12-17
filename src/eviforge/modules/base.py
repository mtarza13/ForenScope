from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict

class ForensicModule(ABC):
    """
    Abstract base class for all forensic modules.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name of the module (e.g., 'strings', 'inventory')."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human readable description."""
        pass

    @property
    def requires_evidence(self) -> bool:
        """Whether this module requires an evidence_id (vs case-scoped)."""
        return True

    @abstractmethod
    def run(self, case_id: str, evidence_id: str | None, **kwargs) -> Dict[str, Any]:
        """
        Execute the module logic.
        Must return a dictionary of results (JSON serializable).
        """
        pass
