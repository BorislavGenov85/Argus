# Argus 🔍

An automated reconnaissance tool for penetration testing, built with Python and Django.
It combines **nmap**, **gobuster**, and **DNS enumeration** into a unified web interface with live results.

> ⚠️ **For use only on systems you have explicit written authorization to test.**

---

## Features

1. **nmap scanning** — scans all 65535 ports with service/version detection (`-sV -sC -p-`)
2. **gobuster directory enumeration** — automatically runs against discovered HTTP/HTTPS services
3. **DNS enumeration** — performs basic record lookups and subdomain brute forcing

Results are streamed **in real time** through WebSockets, so you do not need to wait for the entire scan to finish.

---

## Tech Stack

* **Django 4.2** — web framework
* **Celery + Redis** — asynchronous task processing
* **Django Channels** — WebSocket support for live updates
* **python-nmap** — Python wrapper for nmap
* **dnspython** — DNS resolution and brute forcing
* **subprocess** — execution of gobuster

---

## Installation

### Manual Setup

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install required tools
sudo apt install nmap gobuster redis-server

# Apply migrations
python manage.py migrate

# Start Redis
redis-server

# Start Celery worker
celery -A Argus worker --loglevel=info

# Start ASGI server (recommended)
daphne Argus.asgi:application
```

Open:

```text
http://127.0.0.1:8000
```

---

## Usage

1. Enter a target IP address or domain
2. Select directory and DNS wordlists (or leave the defaults)
3. Click **Start Scan**
4. Monitor live results in the three result tabs
5. Optionally clear previous scans from the database using the **Clear DB** button

---

## Project Structure

```text
Argus/
├── Argus/        # Django settings, ASGI, Celery configuration
├── core/         # Views, models, WebSocket consumers, templates
├── scanner/      # nmap, gobuster, and DNS scanning logic
├── tasks/        # Celery task orchestration
├── static/       # CSS and JavaScript assets
└── manage.py
```

---

## Notes

* Redis must be running before Celery workers are started
* WebSockets require an ASGI server such as Daphne
* Running the project from a VirtualBox shared folder may reduce Redis and SQLite performance
* Long-running scans should eventually support graceful task cancellation and subprocess cleanup

---

## Future Improvements

* Graceful scan cancellation
* Process tracking and cleanup
* Export reports (JSON / HTML / PDF)
* Authentication and user management
* Scan scheduling
* Docker deployment support

---

## Author

Built as a learning project during a transition into the IT and cybersecurity field.

Training:

* SoftUni — Python, Django, and Cybersecurity tracks
* Hack The Box — CJCA learning path
