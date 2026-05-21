"""Airflow operators wrapping packetsonde audits.

Usage:

    from airflow import DAG
    from packetsonde.airflow import PacketSondeAuditOperator

    with DAG("nightly_audit", ...) as dag:
        tls = PacketSondeAuditOperator(
            task_id="audit_tls",
            kind="tls",
            target="mail.example.com:443",
            fail_on="severity>=high",
        )

Findings are pushed to XCom as a list of dicts. The task fails (raises)
on:
  - CLI not found
  - CLI exit code != 0 and != 3
  - --fail-on triggered (exit 3) AND fail_task_on_findings=True

By default --fail-on triggering does NOT fail the Airflow task; it
returns the findings and sets `findings_triggered_fail_on` in the
context. Downstream tasks can branch on that.
"""

from typing import Optional, Sequence

from airflow.models import BaseOperator
from airflow.utils.decorators import apply_defaults

from .client import Client
from .errors import FailOnTriggered


class PacketSondeAuditOperator(BaseOperator):
    """Run `packetsonde audit <kind> <target>` and push findings to XCom."""

    template_fields: Sequence[str] = ("kind", "target", "fail_on", "via")
    ui_color = "#7eb6ff"

    @apply_defaults
    def __init__(self,
                 kind: str,
                 target: str,
                 fail_on: Optional[str] = None,
                 via: Optional[str] = None,
                 binary: Optional[str] = None,
                 fail_task_on_findings: bool = False,
                 **kwargs):
        super().__init__(**kwargs)
        self.kind = kind
        self.target = target
        self.fail_on = fail_on
        self.via = via
        self.binary = binary
        self.fail_task_on_findings = fail_task_on_findings

    def execute(self, context):
        c = Client(binary=self.binary, fail_on=self.fail_on, via=self.via)
        try:
            result = c.audit(self.kind, self.target)
        except FailOnTriggered as e:
            if self.fail_task_on_findings:
                raise
            self.log.warning("--fail-on triggered; returning findings without "
                             "failing task")
            return {
                "findings": [],
                "triggered_fail_on": True,
                "exit_code": 3,
            }
        return {
            "findings":         [f.raw for f in result.findings],
            "triggered_fail_on": False,
            "exit_code":        result.exit_code,
            "duration_ms":      result.duration_ms,
        }


class PacketSondeProbeOperator(BaseOperator):
    """Generic operator for any `packetsonde` verb. argv is the trailing
    argument list after `packetsonde --jsonl`."""

    template_fields: Sequence[str] = ("argv", "via")
    ui_color = "#7eb6ff"

    @apply_defaults
    def __init__(self,
                 argv: Sequence[str],
                 via: Optional[str] = None,
                 binary: Optional[str] = None,
                 **kwargs):
        super().__init__(**kwargs)
        self.argv = list(argv)
        self.via = via
        self.binary = binary

    def execute(self, context):
        c = Client(binary=self.binary, via=self.via)
        result = c.run(*self.argv)
        return [f.raw for f in result.findings]
