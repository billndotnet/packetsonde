"""packetsonde Python client.

Wraps the `packetsonde` CLI as a subprocess and yields findings as
typed dataclasses. The wire format is `v: 1` JSONL on stdout, committed
to stability -- this client only goes obsolete when the CLI changes its
schema, which would be a major version bump.

Quick start:

    from packetsonde import Client
    pc = Client()
    for f in pc.audit("tls", "mail.example.com:443"):
        if f.severity in ("high", "critical"):
            print(f.title, f.target)

Celery and Airflow integrations live in submodules and only import
their dependencies on first use.
"""

from .client import Client, Finding, Severity, RunResult
from .errors import PacketSondeError, FailOnTriggered, CLINotFound

__all__ = [
    "Client",
    "Finding",
    "Severity",
    "RunResult",
    "PacketSondeError",
    "FailOnTriggered",
    "CLINotFound",
]

__version__ = "1.6.0"
