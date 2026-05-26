from scanner.nmap_module import NmapModule
from scanner.gobuster_module import GobusterModule
from scanner.vhost_module import VHostModule
from scanner.dns_module import DNSModule

# Module registry — order matters for dependency resolution
DISCOVERY_MODULES = [
    NmapModule(),
    GobusterModule(),
]

EXPANSION_MODULES = [
    VHostModule(),
    DNSModule(),
]

ALL_MODULES = DISCOVERY_MODULES + EXPANSION_MODULES
