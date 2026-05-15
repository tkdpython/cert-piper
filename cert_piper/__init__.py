"""cert-piper: Display X.509 certificate information from piped input."""

try:
    from cert_piper._version import version as __version__
except (ImportError, SyntaxError):
    __version__ = "0.0.0.dev0"
