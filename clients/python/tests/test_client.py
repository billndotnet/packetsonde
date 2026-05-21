"""Tests for the subprocess wrapper using a tiny fake `packetsonde`
binary that emits a known JSONL stream. No real audits are performed."""

import os
import stat
import sys
from pathlib import Path

import pytest

from packetsonde import Client, Severity, RunResult
from packetsonde.errors import FailOnTriggered, PacketSondeError


def make_fake_cli(tmp_path: Path, stdout: str, exit_code: int = 0,
                  stderr: str = "") -> Path:
    """Create a tiny shell script that mimics `packetsonde --jsonl ...`."""
    p = tmp_path / "fake_packetsonde"
    # The fake CLI emits `stdout` verbatim, prints `stderr`, exits with
    # `exit_code`. Write content to a tmp file so embedded shell metas in
    # the test fixture don't get interpreted.
    out_file  = tmp_path / "fake_stdout"
    err_file  = tmp_path / "fake_stderr"
    out_file.write_text(stdout)
    err_file.write_text(stderr)
    body = (
        "#!/bin/sh\n"
        f"cat '{out_file}'\n"
        f"cat '{err_file}' >&2\n"
        f"exit {exit_code}\n"
    )
    p.write_text(body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return p


SAMPLE_FINDING = (
    '{"v":1,"id":"01KTEST","run_id":"01KRUN","ts":"2026-05-20T00:00:00Z",'
    '"source":"cli.audit.tls","host":"box","kind":"tls.weak_protocol",'
    '"severity":"high","confidence":"firm","title":"TLS 1.0 negotiated",'
    '"target":{"ip":"10.0.0.1","hostname":"x","port":443},'
    '"evidence":{"protocol":"TLSv1"}}'
)


def test_parses_findings(tmp_path):
    fake = make_fake_cli(tmp_path, SAMPLE_FINDING)
    c = Client(binary=str(fake))
    r = c.audit("tls", "x:443")
    assert r.exit_code == 0
    assert len(r.findings) == 1
    f = r.findings[0]
    assert f.kind == "tls.weak_protocol"
    assert f.severity == Severity.HIGH
    assert f.target.port == 443


def test_via_agent_field(tmp_path):
    out = (
        '{"v":1,"id":"x","run_id":"y","ts":"t","source":"cli.audit.tls",'
        '"host":"agentbox","kind":"tls.metadata","severity":"info",'
        '"confidence":"confirmed","title":"t","target":{"ip":"1.1.1.1","port":443},'
        '"evidence":{},"via_agent":"trunkbox"}'
    )
    fake = make_fake_cli(tmp_path, out)
    c = Client(binary=str(fake))
    r = c.audit("tls", "x:443")
    assert r.findings[0].via_agent == "trunkbox"


def test_ignores_non_jsonl_garbage(tmp_path):
    out = "garbage line\n" + SAMPLE_FINDING + "\nanother garbage"
    fake = make_fake_cli(tmp_path, out)
    c = Client(binary=str(fake))
    r = c.audit("tls", "x:443")
    assert len(r.findings) == 1


def test_max_severity(tmp_path):
    info = SAMPLE_FINDING.replace('"high"', '"info"').replace('"tls.weak_protocol"',
                                                              '"tls.metadata"')
    out  = SAMPLE_FINDING + "\n" + info
    fake = make_fake_cli(tmp_path, out)
    c = Client(binary=str(fake))
    r = c.audit("tls", "x:443")
    assert r.max_severity() == Severity.HIGH


def test_fail_on_triggered(tmp_path):
    fake = make_fake_cli(tmp_path, SAMPLE_FINDING, exit_code=3)
    c = Client(binary=str(fake))
    with pytest.raises(FailOnTriggered):
        list(c.stream("audit", "tls", "x:443"))


def test_nonzero_exit_raises(tmp_path):
    fake = make_fake_cli(tmp_path, SAMPLE_FINDING, exit_code=1,
                         stderr="some error")
    c = Client(binary=str(fake))
    with pytest.raises(PacketSondeError):
        list(c.stream("audit", "tls", "x:443"))


def test_streaming_yields_in_order(tmp_path):
    a = SAMPLE_FINDING
    b = SAMPLE_FINDING.replace("01KTEST", "01KTEST2")
    fake = make_fake_cli(tmp_path, a + "\n" + b)
    c = Client(binary=str(fake))
    got = list(c.stream("audit", "tls", "x:443"))
    assert [f.id for f in got] == ["01KTEST", "01KTEST2"]
