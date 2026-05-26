"""
EventBus — strict-schema event dispatch to WebSocket.

Every event going to the frontend must go through here. No ad-hoc
dicts with random keys — the schema is enforced at the point of emission.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, asdict
from typing import Any, Callable


class EventType(str, enum.Enum):
    # Lifecycle
    SCAN_STARTED = 'scan_started'
    SCAN_COMPLETED = 'scan_completed'
    SCAN_FAILED = 'scan_failed'
    SCAN_STOPPED = 'scan_stopped'

    # Module lifecycle
    MODULE_STARTED = 'module_started'
    MODULE_COMPLETED = 'module_completed'
    MODULE_FAILED = 'module_failed'
    MODULE_SKIPPED = 'module_skipped'

    # Results
    PORT_FOUND = 'port_found'
    DIRECTORY_FOUND = 'directory_found'
    VHOST_FOUND = 'vhost_found'
    DNS_RECORD_FOUND = 'dns_record_found'
    DOMAIN_DETECTED = 'domain_detected'

    # Domain confirmation flow
    DOMAINS_AWAITING = 'domains_awaiting'
    DOMAINS_CONFIRMED = 'domains_confirmed'

    # Log
    LOG = 'log'


@dataclass
class ScanEvent:
    """Immutable event object. Serializes cleanly to JSON."""
    type: EventType
    module: str = ''
    message: str = ''
    data: dict[str, Any] | None = None

    def to_dict(self) -> dict:
        d = {
            'type': self.type.value,
        }
        if self.module:
            d['module'] = self.module
        if self.message:
            d['message'] = self.message
        if self.data:
            d['data'] = self.data
        return d


# Type alias for the dispatch function injected by the caller (Celery task)
EventDispatcher = Callable[[ScanEvent], None]


class EventBus:
    """
    Thin wrapper around the dispatch function.

    Usage:
        bus = EventBus(send_ws_update_fn)
        bus.emit(EventType.MODULE_STARTED, module='nmap')
        bus.log('nmap', 'Starting port scan...')
    """

    def __init__(self, dispatcher: EventDispatcher):
        self._dispatch = dispatcher

    def emit(
        self,
        event_type: EventType,
        module: str = '',
        message: str = '',
        data: dict[str, Any] | None = None,
    ) -> None:
        event = ScanEvent(
            type=event_type,
            module=module,
            message=message,
            data=data,
        )
        self._dispatch(event)

    def log(self, module: str, message: str) -> None:
        self.emit(EventType.LOG, module=module, message=message)

    def module_started(self, module: str, message: str = '') -> None:
        self.emit(
            EventType.MODULE_STARTED,
            module=module,
            message=message or f'Starting {module}...',
        )

    def module_completed(self, module: str, message: str = '') -> None:
        self.emit(
            EventType.MODULE_COMPLETED,
            module=module,
            message=message or f'{module} completed.',
        )

    def module_failed(self, module: str, error: str) -> None:
        self.emit(
            EventType.MODULE_FAILED,
            module=module,
            message=error,
        )

    def module_skipped(self, module: str, reason: str) -> None:
        self.emit(
            EventType.MODULE_SKIPPED,
            module=module,
            message=reason,
        )
