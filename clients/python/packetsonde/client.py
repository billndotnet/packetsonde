"""Subprocess-based client for the packetsonde CLI."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterator, Mapping, Optional, Sequence

from .errors import CLINotFound, FailOnTriggered, PacketSondeError


class Severity(str, Enum):
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"

    @classmethod
    def coerce(cls, value: str) -> "Severity":
        try:
            return cls(value)
        except ValueError:
            return cls.INFO


@dataclass(frozen=True)
class Target:
    ip:       Optional[str] = None
    hostname: Optional[str] = None
    port:     Optional[int] = None


@dataclass(frozen=True)
class Finding:
    """One finding record as emitted by the CLI. The dict layout matches
    the v:1 schema documented in docs/specs/2026-05-18-packetsonde-cli-design.md."""
    v:          int
    id:         str
    run_id:     str
    ts:         str
    source:     str
    host:       str
    kind:       str
    severity:   Severity
    confidence: str
    title:      str
    target:     Target
    evidence:   Mapping
    via_agent:  Optional[str] = None
    raw:        Mapping       = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: Mapping) -> "Finding":
        t = d.get("target") or {}
        return cls(
            v          = int(d.get("v", 1)),
            id         = d.get("id", ""),
            run_id     = d.get("run_id", ""),
            ts         = d.get("ts", ""),
            source     = d.get("source", ""),
            host       = d.get("host", ""),
            kind       = d.get("kind", ""),
            severity   = Severity.coerce(d.get("severity", "info")),
            confidence = d.get("confidence", ""),
            title      = d.get("title", ""),
            target     = Target(
                ip       = t.get("ip"),
                hostname = t.get("hostname"),
                port     = t.get("port"),
            ),
            evidence   = d.get("evidence", {}),
            via_agent  = d.get("via_agent"),
            raw        = d,
        )


@dataclass
class RunResult:
    """Aggregate result of a single CLI invocation."""
    findings:     list[Finding]
    exit_code:    int
    duration_ms:  int
    stderr:       str

    def by_severity(self) -> Mapping[Severity, list[Finding]]:
        out: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            out[f.severity].append(f)
        return out

    def max_severity(self) -> Optional[Severity]:
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                 Severity.LOW, Severity.INFO]
        for sev in order:
            for f in self.findings:
                if f.severity == sev:
                    return sev
        return None


def _locate(binary: Optional[str]) -> str:
    if binary and os.path.isabs(binary):
        return binary
    candidate = binary or "packetsonde"
    found = shutil.which(candidate)
    if not found:
        raise CLINotFound(f"`{candidate}` not found on $PATH; "
                          f"pass binary= to Client() or install the CLI")
    return found


class Client:
    """High-level Python interface.

    By default the client locates `packetsonde` on $PATH. Pass `binary=`
    to override (useful for tests, sandboxed environments, or running
    against a development build).

    Long-running runs use :meth:`stream`, which yields findings as they
    arrive. Short runs can use :meth:`audit` / :meth:`scan` for the
    aggregate RunResult.
    """

    def __init__(self,
                 binary: Optional[str] = None,
                 fail_on: Optional[str] = None,
                 via: Optional[str] = None):
        self.binary  = _locate(binary)
        self.fail_on = fail_on
        self.via     = via

    # ---- low-level streaming ---------------------------------------

    def stream(self, *argv: str,
               extra_env: Optional[Mapping[str, str]] = None
               ) -> Iterator[Finding]:
        """Yield Finding objects as the CLI emits them. Iterates the
        subprocess's stdout line-by-line. Raises PacketSondeError on
        non-zero exit (other than the --fail-on signal exit code 3,
        which raises FailOnTriggered after yielding all findings)."""
        argv = list(self._build_argv(argv))
        env  = dict(os.environ)
        if extra_env: env.update(extra_env)
        proc = subprocess.Popen(
            argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if d.get("v") == 1:
                    yield Finding.from_dict(d)
        finally:
            proc.wait()
            if proc.returncode == 3:
                raise FailOnTriggered(
                    f"{argv[0]} exited 3 (--fail-on matched)", findings=[],
                )
            if proc.returncode != 0:
                stderr = proc.stderr.read() if proc.stderr else ""
                raise PacketSondeError(
                    f"{argv[0]} exited {proc.returncode}: {stderr.strip()}"
                )

    # ---- aggregating wrappers --------------------------------------

    def run(self, *argv: str,
            extra_env: Optional[Mapping[str, str]] = None) -> RunResult:
        """Run any CLI invocation; return the aggregate RunResult.

        Use :meth:`audit`, :meth:`scan_ports`, :meth:`probe_tcp` etc. for
        verb-specific sugar."""
        import time
        t0 = time.monotonic()
        argv = list(self._build_argv(argv))
        env  = dict(os.environ)
        if extra_env: env.update(extra_env)
        proc = subprocess.run(
            argv, env=env, capture_output=True, text=True, check=False,
        )
        findings = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if d.get("v") == 1:
                findings.append(Finding.from_dict(d))
        return RunResult(
            findings    = findings,
            exit_code   = proc.returncode,
            duration_ms = int((time.monotonic() - t0) * 1000),
            stderr      = proc.stderr,
        )

    # ---- verb sugar ------------------------------------------------

    def audit(self, kind: str, *targets: str, **kwargs) -> RunResult:
        return self.run("audit", kind, *targets, **kwargs)

    def scan_ports(self, target: str, ports: Optional[str] = None,
                   **kwargs) -> RunResult:
        argv = ["scan", "ports", target]
        if ports: argv += ["-p", ports]
        return self.run(*argv, **kwargs)

    def scan_udp(self, target: str, ports: Optional[str] = None,
                 **kwargs) -> RunResult:
        argv = ["scan", "udp", target]
        if ports: argv += ["-p", ports]
        return self.run(*argv, **kwargs)

    def probe_tcp(self, target: str, **kwargs) -> RunResult:
        return self.run("probe", "tcp", target, **kwargs)

    def traceroute(self, target: str,
                   proto: str = "udp", mode: str = "classic",
                   port: Optional[int] = None, **kwargs) -> RunResult:
        argv = ["probe", "traceroute", target, "--proto", proto, "--mode", mode]
        if port is not None: argv += ["--port", str(port)]
        return self.run(*argv, **kwargs)

    def discover_neighbors(self, **kwargs) -> RunResult:
        return self.run("discover", "neighbors", **kwargs)

    def discover_agents(self, target: str, **kwargs) -> RunResult:
        return self.run("discover", "agents", target, **kwargs)

    # ---- internals -------------------------------------------------

    def _build_argv(self, argv: Sequence[str]) -> Iterator[str]:
        yield self.binary
        yield "--jsonl"
        if self.fail_on:
            yield "--fail-on"
            yield self.fail_on
        if self.via:
            yield "--via"
            yield self.via
        for a in argv:
            yield a
