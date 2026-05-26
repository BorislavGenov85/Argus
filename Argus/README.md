# Argus v2.0 — Modular Recon Pipeline

A Django + Celery + Channels-based reconnaissance tool refactored from a linear
scanner into a modular pipeline architecture.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Celery Tasks                        │
│                                                         │
│   run_discovery ──────────────── run_expansion          │
│   (Phase 1)                      (Phase 2)              │
│        │                              │                 │
│        ▼                              ▼                 │
│   ┌─────────┐                    ┌─────────┐            │
│   │Orchestr.│                    │Orchestr.│            │
│   └────┬────┘                    └────┬────┘            │
│        │                              │                 │
│   ┌────▼────────────┐    ┌────────────▼────────────┐    │
│   │ Discovery Phase │    │   Expansion Phase       │    │
│   │                 │    │                         │    │
│   │  NmapModule     │    │  VHostModule (ffuf)     │    │
│   │  GobusterModule │    │  DNSModule              │    │
│   └────────┬────────┘    └────────────┬────────────┘    │
│            │                          │                 │
│            ▼                          ▼                 │
│   ┌──────────────────────────────────────────┐          │
│   │            ReconContext                   │          │
│   │  (shared mutable state, thread-safe)     │          │
│   │                                          │          │
│   │  open_ports, http_services,              │          │
│   │  discovered_domains, confirmed_domains,  │          │
│   │  findings, completed_modules             │          │
│   └──────────────────────────────────────────┘          │
│                        │                                │
│                        ▼                                │
│              ┌───────────────┐                          │
│              │  EventBus     │──── WebSocket ──── UI    │
│              └───────────────┘                          │
└─────────────────────────────────────────────────────────┘
```

## Key Design Decisions

### Two-phase scan (no worker polling)

The old design blocked a Celery worker in a `time.sleep()` loop for up to 5
minutes waiting for domain confirmation via Redis. Now:

1. `run_discovery` completes → sets `status=awaiting_domains` → worker freed
2. Frontend shows domain modal → user confirms
3. `POST /scan/{id}/continue/` with JSON body → triggers `run_expansion`

No polling. No timeout. No wasted resources.

### Modular pipeline (not "event-driven")

Each scanner is a `ReconModule` with:
- `name` — unique identifier
- `phase` — `'discovery'` or `'expansion'`
- `requires` — list of module names that must complete first
- `should_run(context)` — precondition check
- `run(context, bus)` — the actual scan

The `Orchestrator` runs modules sequentially with dependency checks. This is a
dependency-graph pipeline, not an event-driven system.

### ProcessManager

Centralized subprocess lifecycle replaces per-field PID tracking on the Django
model. Handles SIGTERM → wait → SIGKILL cleanup.

### Domain extraction with source tagging

`DomainExtractor` pulls domains from TLS certs, HTTP redirects, HTML bodies,
and gobuster URLs. Each domain is tagged with its source (`tls_san`, `tls_cn`,
`http_redirect`, etc.) for filtering. No confidence scores — source tags give
the same filtering power without float threshold maintenance.

### Strict WebSocket event schema

All events use an `EventType` enum. The frontend has a dispatch table
(`EVENT_HANDLERS`) keyed by event type. No ad-hoc `stage`/`status` dicts.

## Project Structure

```
argus/
├── Argus/                  # Django project config
│   ├── settings.py
│   ├── celery.py
│   ├── asgi.py
│   └── urls.py
├── core/                   # Django app (models, views, WS consumer)
│   ├── models.py           # ScanSession, PortResult, etc.
│   ├── views.py            # HTTP API (start, continue, stop)
│   ├── consumers.py        # WebSocket (one-way: server → client)
│   ├── urls.py
│   └── routing.py
├── pipeline/               # Core pipeline abstractions
│   ├── context.py          # ReconContext (shared state)
│   ├── base_module.py      # ReconModule ABC
│   ├── orchestrator.py     # Runs modules in dependency order
│   ├── events.py           # EventBus + EventType enum
│   ├── finding.py          # Finding + FindingType + Severity
│   ├── process_manager.py  # Subprocess lifecycle
│   └── domain_extractor.py # Domain extraction + normalisation
├── scanner/                # Concrete modules
│   ├── nmap_module.py      # Port scanning
│   ├── gobuster_module.py  # Directory enumeration
│   ├── vhost_module.py     # VHost discovery (ffuf)
│   └── dns_module.py       # DNS enumeration
├── tasks/
│   └── scan_tasks.py       # Celery tasks (discovery + expansion)
├── templates/core/
│   └── index.html
├── staticfiles/core/
│   ├── css/style.css
│   └── js/main.js
├── requirements.txt
└── manage.py
```

## Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Required system tools
# nmap, gobuster, ffuf must be in PATH

# Run migrations
python manage.py makemigrations
python manage.py migrate

# Start Redis
redis-server

# Start Celery worker
celery -A Argus worker -l info

# Start Django (ASGI for WebSockets)
daphne -b 0.0.0.0 -p 8000 Argus.asgi:application
```

## Adding a New Module

```python
from pipeline.base_module import ReconModule

class MyModule(ReconModule):
    name = 'my_scanner'
    phase = 'discovery'       # or 'expansion'
    requires = ['nmap']       # modules that must complete first

    def should_run(self, context):
        return context.has_http  # your precondition

    def run(self, context, bus):
        bus.log(self.name, 'Starting...')

        # Do work, check context.should_stop periodically
        # Add results: context.add_finding(...)
        # Emit events: bus.emit(EventType.PORT_FOUND, ...)
```

Then register it in `scanner/__init__.py`.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/scan/start/` | Start phase 1 (discovery) |
| POST | `/scan/{id}/continue/` | Confirm domains, start phase 2 |
| POST | `/scan/{id}/stop/` | Stop scan |
| GET | `/scan/{id}/status/` | Poll status (fallback) |
| POST | `/scan/{id}/delete/` | Delete session |
| POST | `/db/clear/` | Clear all sessions |

## WebSocket Events

| Event | Direction | Description |
|-------|-----------|-------------|
| `scan_started` | server→client | Scan begun |
| `module_started` | server→client | Module execution started |
| `port_found` | server→client | Open port discovered |
| `directory_found` | server→client | Directory/file found |
| `domains_awaiting` | server→client | Domains need confirmation |
| `domains_confirmed` | server→client | Phase 2 starting |
| `vhost_found` | server→client | Virtual host discovered |
| `dns_record_found` | server→client | DNS record found |
| `module_completed` | server→client | Module finished |
| `scan_completed` | server→client | All phases done |
