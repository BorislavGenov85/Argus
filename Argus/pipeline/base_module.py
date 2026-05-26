"""
ReconModule — base class for all scanner modules.

Each module declares:
  - name: unique identifier
  - phase: 'discovery' or 'expansion'
  - requires: list of module names that must complete first
  - should_run(): whether the module has enough context to execute
  - run(): the actual scan logic, receives context + event bus
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pipeline.context import ReconContext
    from pipeline.events import EventBus


class ReconModule(ABC):
    name: str = ''
    phase: str = 'discovery'  # 'discovery' or 'expansion'
    requires: list[str] = []  # modules that must complete before this one

    @abstractmethod
    def should_run(self, context: ReconContext) -> bool:
        """Return True if this module has enough data to execute."""
        ...

    @abstractmethod
    def run(self, context: ReconContext, bus: EventBus) -> None:
        """
        Execute the scan. Must:
        - Check context.should_stop periodically
        - Populate context with results
        - Emit events via bus
        - NOT catch exceptions silently (let orchestrator handle)
        """
        ...

    def skip_reason(self, context: ReconContext) -> str:
        """Human-readable reason when should_run returns False."""
        return f'{self.name}: preconditions not met.'

    def __repr__(self):
        return f'<{self.__class__.__name__} name={self.name!r} phase={self.phase!r}>'
