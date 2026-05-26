"""
Orchestrator — runs modules in dependency order within a phase.

Two phases:
  1. Discovery: nmap, gobuster, domain extraction
     Ends with domains_awaiting → pauses, returns control to Celery task
  2. Expansion: vhost (ffuf), dns enumeration
     Runs after user confirms domains

This is NOT event-driven — it's a sequential dependency-graph pipeline
with conditional execution. Calling it what it is.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pipeline.context import ReconContext
    from pipeline.events import EventBus, EventType
    from pipeline.process_manager import ProcessManager
    from pipeline.base_module import ReconModule


class Orchestrator:
    """
    Stateless runner. Takes a list of modules and a context, runs them
    in order respecting dependencies.
    """

    def __init__(
        self,
        modules: list[ReconModule],
        context: ReconContext,
        bus: EventBus,
        process_manager: ProcessManager,
    ):
        self.modules = modules
        self.context = context
        self.bus = bus
        self.pm = process_manager

    def run_phase(self, phase: str) -> bool:
        """
        Run all modules matching `phase` in order.

        Returns True if completed normally, False if stopped.
        """
        from pipeline.events import EventType

        phase_modules = [m for m in self.modules if m.phase == phase]

        for module in phase_modules:
            if self.context.should_stop:
                self.bus.emit(EventType.SCAN_STOPPED, message='Scan stopped by user.')
                self.pm.cleanup()
                return False

            # Check dependencies
            unmet = [
                r for r in module.requires
                if r not in self.context.completed_modules
            ]
            if unmet:
                self.bus.module_skipped(
                    module.name,
                    f'Skipped — waiting for: {", ".join(unmet)}',
                )
                continue

            # Check preconditions
            if not module.should_run(self.context):
                self.bus.module_skipped(module.name, module.skip_reason(self.context))
                continue

            # Run
            self.bus.module_started(module.name)

            try:
                module.run(self.context, self.bus)

                if self.context.should_stop:
                    self.pm.cleanup()
                    self.bus.emit(EventType.SCAN_STOPPED, message='Scan stopped by user.')
                    return False

                self.context.mark_completed(module.name)
                self.bus.module_completed(module.name)

            except Exception as e:
                self.context.mark_failed(module.name)
                self.bus.module_failed(module.name, str(e))
                # Continue with next module — don't fail the whole scan
                continue

        return True
