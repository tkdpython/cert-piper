"""Tests for cert_piper.cli."""

import sys
from io import StringIO
from unittest.mock import patch

import pytest

from cert_piper.cli import main


class TestCliMain:
    def _run(self, stdin_data, extra_args=None):
        """Run main() with fake stdin, return (stdout, exit_code)."""
        args = ["cert-piper"] + (extra_args or [])
        stdout_capture = StringIO()
        with patch("sys.argv", args), \
             patch("sys.stdin", StringIO(stdin_data)), \
             patch("sys.stdin.isatty", return_value=False):
            try:
                with patch("sys.stdout", stdout_capture):
                    main()
                return stdout_capture.getvalue(), 0
            except SystemExit as exc:
                return stdout_capture.getvalue(), exc.code

    def test_exits_on_tty(self):
        with patch("sys.argv", ["cert-piper"]), \
             patch("sys.stdin.isatty", return_value=True):
            with pytest.raises(SystemExit):
                main()

    def test_exits_on_empty_input(self):
        _, code = self._run("")
        assert code != 0

    def test_exits_when_no_certs_found(self):
        _, code = self._run("not a certificate at all")
        assert code != 0

    def test_version_flag(self):
        with patch("sys.argv", ["cert-piper", "--version"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    def test_single_cert(self, leaf_pem):
        """Passing a PEM cert should succeed (exit code 0 / None)."""
        with patch("sys.argv", ["cert-piper"]), \
             patch("sys.stdin", StringIO(leaf_pem)), \
             patch("sys.stdin.isatty", return_value=False):
            # display_certs writes to a rich Console; just check it doesn't raise
            main()

    def test_base64_encoded_cert(self, leaf_b64_pem):
        """Passing a base64-encoded PEM cert should succeed."""
        with patch("sys.argv", ["cert-piper"]), \
             patch("sys.stdin", StringIO(leaf_b64_pem)), \
             patch("sys.stdin.isatty", return_value=False):
            main()

    def test_bundle_cert(self, bundle_pem):
        """Passing a PEM bundle (two certs) should succeed."""
        with patch("sys.argv", ["cert-piper"]), \
             patch("sys.stdin", StringIO(bundle_pem)), \
             patch("sys.stdin.isatty", return_value=False):
            main()
