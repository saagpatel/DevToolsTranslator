#!/usr/bin/env python3
"""Regression tests for process-context gate harness behavior."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
from process_context_gate import broker_capture  # noqa: E402


class _BrokenPipeStdin:
    closed = False

    def write(self, payload: bytes) -> int:
        return len(payload)

    def flush(self) -> None:
        raise BrokenPipeError(32, "simulated early child close")

    def close(self) -> None:
        self.closed = True


class _Output:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def read(self) -> bytes:
        return self.payload


class _RejectedProcess:
    def __init__(self) -> None:
        self.stdin = _BrokenPipeStdin()
        self.stdout = _Output(b'{"type":"rejected","code":"consent_required"}\n')
        self.stderr = _Output(b"")

    def wait(self, timeout: int) -> int:
        return 7

    def kill(self) -> None:
        raise AssertionError("early rejection must not require a kill")


class BrokerCaptureTests(unittest.TestCase):
    def test_early_rejection_is_returned_instead_of_raising_broken_pipe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch(
                "process_context_gate.subprocess.Popen",
                return_value=_RejectedProcess(),
            ):
                code, stdout, stderr, evidence = broker_capture(
                    Path("/unused-helper"), Path(directory), {}
                )

        self.assertEqual(code, 7)
        self.assertIn(b'"code":"consent_required"', stdout)
        self.assertEqual(stderr, b"")
        self.assertEqual(evidence, b"")


if __name__ == "__main__":
    unittest.main()
