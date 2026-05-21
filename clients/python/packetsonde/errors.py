class PacketSondeError(Exception):
    """Base class for all client errors."""


class CLINotFound(PacketSondeError):
    """The `packetsonde` binary couldn't be located on $PATH or via
    the client's `binary=` argument."""


class FailOnTriggered(PacketSondeError):
    """The CLI exited with code 3 because --fail-on matched a finding.
    The run still produced findings; this is signal, not a failure."""

    def __init__(self, message: str, findings: list):
        super().__init__(message)
        self.findings = findings
