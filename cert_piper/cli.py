"""CLI entry point for cert-piper."""

import argparse
import sys

from cert_piper import __version__
from cert_piper.cert_analyzer import extract_certs_from_input
from cert_piper.display import display_certs


def _build_parser():
    # type: () -> argparse.ArgumentParser
    parser = argparse.ArgumentParser(
        prog="cert-piper",
        description=(
            "Pipe certificate data into cert-piper to display X.509 certificate information.\n\n"
            "Supports PEM certificates, PEM bundles, and base64-encoded certificates.\n\n"
            "Examples:\n"
            "  cat mycert.pem | cert-piper\n"
            "  cat mycert.pem | python3 -m cert_piper\n"
            "  cat bundle.pem | cert-piper --paging\n"
            "  cat encoded.b64 | cert-piper"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s {0}".format(__version__),
    )
    parser.add_argument(
        "--paging",
        action="store_true",
        help="Display output via a pager (like 'more').",
    )
    return parser


def main():
    # type: () -> None
    parser = _build_parser()
    args = parser.parse_args()

    if sys.stdin.isatty():
        parser.error(
            "No input detected. Pipe certificate data into cert-piper.\n"
            "  Example: cat mycert.pem | cert-piper"
        )

    raw = sys.stdin.read()
    if not raw.strip():
        parser.error("Received empty input from stdin.")

    certs, warnings, detected_base64 = extract_certs_from_input(raw)

    if not certs and not warnings:
        sys.exit("No certificates found in the input.")

    if detected_base64:
        print("(base64-encoded input detected and decoded)")

    display_certs(certs, warnings, paging=args.paging)


if __name__ == "__main__":
    main()
