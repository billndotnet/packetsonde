"""Celery task wrappers for packetsonde audits.

Usage:

    from celery import Celery
    from packetsonde.celery_tasks import register_tasks

    app = Celery("scanner", broker="redis://localhost:6379/0")
    register_tasks(app)

    # Then from anywhere:
    result = app.send_task("packetsonde.audit",
                          args=["tls", "mail.example.com:443"])
    findings = result.get(timeout=30)
    for f in findings:
        if f["severity"] in ("high", "critical"):
            ...

Tasks return findings as plain dicts (Finding.raw) so they serialize
cleanly through Celery's default JSON backend without registering
custom encoders.
"""

from typing import List, Mapping

from .client import Client


def register_tasks(app, binary: str = None):
    """Register packetsonde.* tasks on `app`.

    Returns the dict of task names -> task objects so callers can hold
    references or inspect them."""

    @app.task(name="packetsonde.audit", bind=True)
    def audit_task(self, kind: str, *targets: str,
                   fail_on: str = None, via: str = None) -> List[Mapping]:
        c = Client(binary=binary, fail_on=fail_on, via=via)
        r = c.audit(kind, *targets)
        return [f.raw for f in r.findings]

    @app.task(name="packetsonde.scan_ports", bind=True)
    def scan_ports_task(self, target: str, ports: str = None,
                        fail_on: str = None, via: str = None) -> List[Mapping]:
        c = Client(binary=binary, fail_on=fail_on, via=via)
        r = c.scan_ports(target, ports=ports)
        return [f.raw for f in r.findings]

    @app.task(name="packetsonde.traceroute", bind=True)
    def traceroute_task(self, target: str, proto: str = "udp",
                        mode: str = "classic") -> List[Mapping]:
        c = Client(binary=binary)
        r = c.traceroute(target, proto=proto, mode=mode)
        return [f.raw for f in r.findings]

    return {
        "audit":      audit_task,
        "scan_ports": scan_ports_task,
        "traceroute": traceroute_task,
    }
