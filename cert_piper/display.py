"""Rich terminal output for cert-piper.

Compatible with rich 10.x through rich 13.x+.
"""

from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

# Threshold in days at which we warn about upcoming expiry
_EXPIRY_WARN_DAYS = 30
_EXPIRY_CRITICAL_DAYS = 7

# Column widths for the label column
_LABEL_WIDTH = 26


def _validity_style(days_remaining, is_expired):
    # type: (int, bool) -> str
    if is_expired or days_remaining <= _EXPIRY_CRITICAL_DAYS:
        return "bold red"
    if days_remaining <= _EXPIRY_WARN_DAYS:
        return "bold yellow"
    return "bold green"


def _validity_icon(days_remaining, is_expired):
    # type: (int, bool) -> str
    if is_expired:
        return "\u2717 EXPIRED"
    if days_remaining <= _EXPIRY_CRITICAL_DAYS:
        return "\u26a0 CRITICAL ({0} days)".format(days_remaining)
    if days_remaining <= _EXPIRY_WARN_DAYS:
        return "\u26a0 EXPIRING SOON ({0} days)".format(days_remaining)
    return "\u2713 Valid ({0} days remaining)".format(days_remaining)


def _fmt_dt(dt):
    # type: (object) -> str
    """Format a datetime as a friendly UTC string."""
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "N/A"


def _build_cert_table(cert_info):
    # type: (dict) -> Table
    """Build a rich Table containing all sections for one certificate."""
    tbl = Table.grid(padding=(0, 1), expand=True)
    tbl.add_column(
        style="dim",
        justify="right",
        no_wrap=True,
        min_width=_LABEL_WIDTH,
        max_width=_LABEL_WIDTH,
    )
    tbl.add_column(ratio=1)

    days = cert_info["days_remaining"]
    expired = cert_info["is_expired"]

    def section(title):
        # type: (str) -> None
        tbl.add_row("", "")
        tbl.add_row(
            "",
            Text(title, style="bold bright_white underline"),
        )

    def row(label, value, value_style=""):
        # type: (str, object, str) -> None
        if isinstance(value, Text):
            val = value
        else:
            val = Text(str(value), style=value_style)
        tbl.add_row(Text(label, style="dim"), val)

    # ── Subject ──────────────────────────────────────────────────
    section("\U0001f4cb  Subject")
    for k, v in cert_info["subject"]:
        row(k, v)

    # ── Issuer ───────────────────────────────────────────────────
    section("\U0001f3db   Issuer")
    for k, v in cert_info["issuer"]:
        row(k, v)

    # ── Validity ─────────────────────────────────────────────────
    validity_style = _validity_style(days, expired)
    section("\u23f1   Validity")
    row("Not Before", _fmt_dt(cert_info["not_before"]))
    row("Not After", _fmt_dt(cert_info["not_after"]))
    row("Status", Text(_validity_icon(days, expired), style=validity_style))

    # ── Public Key ───────────────────────────────────────────────
    section("\U0001f511  Public Key")
    row("Algorithm", cert_info["key_type"])
    row(
        "Key Size",
        "{0} bits".format(cert_info["key_bits"]) if cert_info["key_bits"] else "N/A",
    )
    row("Signature Algorithm", cert_info["signature_algorithm"])

    # ── SANs ─────────────────────────────────────────────────────
    sans = cert_info["sans"]
    section(
        "\U0001f310  Subject Alternative Names  [{0}]".format(len(sans))
        if sans
        else "\U0001f310  Subject Alternative Names  [none]"
    )
    if sans:
        for san_type, san_val in sans:
            row(san_type, san_val, value_style="cyan")
    else:
        row("", Text("(none)", style="dim"))

    # ── Key Usage ────────────────────────────────────────────────
    section("\U0001f6e1   Key Usage")
    if cert_info["key_usage"]:
        row("Key Usage", ", ".join(cert_info["key_usage"]))
    else:
        row("Key Usage", Text("(not set)", style="dim"))
    if cert_info["extended_key_usage"]:
        row("Extended Key Usage", ", ".join(cert_info["extended_key_usage"]))
    else:
        row("Extended Key Usage", Text("(not set)", style="dim"))

    # ── OCSP / Revocation ────────────────────────────────────────
    section("\U0001f512  OCSP / Revocation")
    if cert_info["ocsp_urls"]:
        for url in cert_info["ocsp_urls"]:
            row("OCSP URL", url)
    else:
        row("OCSP URL", Text("(not present)", style="dim"))
    if cert_info["ca_issuer_urls"]:
        for url in cert_info["ca_issuer_urls"]:
            row("CA Issuers URL", url)
    if cert_info["crl_urls"]:
        for url in cert_info["crl_urls"]:
            row("CRL Distribution Point", url)
    row(
        "OCSP Must-Staple",
        Text("Yes", style="green")
        if cert_info["ocsp_must_staple"]
        else Text("No", style="dim"),
    )

    # ── Fingerprints ─────────────────────────────────────────────
    section("\U0001f50d  Fingerprints")
    row("SHA-256", cert_info["fingerprint_sha256"])
    row("SHA-1", Text(cert_info["fingerprint_sha1"], style="dim yellow"))

    # ── Additional Details ───────────────────────────────────────
    section("\u2139   Additional Details")
    row("Serial Number", cert_info["serial"])
    row(
        "Self-Signed",
        Text("Yes", style="yellow")
        if cert_info["is_self_signed"]
        else Text("No", style="dim"),
    )
    row(
        "Is CA",
        Text("Yes", style="cyan")
        if cert_info["is_ca"]
        else Text("No", style="dim"),
    )
    if cert_info["path_length"] is not None:
        row("Path Length Constraint", str(cert_info["path_length"]))
    if cert_info["subject_key_id"]:
        row("Subject Key ID", cert_info["subject_key_id"])
    if cert_info["authority_key_id"]:
        row("Authority Key ID", cert_info["authority_key_id"])

    tbl.add_row("", "")
    return tbl


def _cert_panel(cert_info, index, total):
    # type: (dict, int, int) -> Panel
    """Return a rich Panel wrapping the cert table."""
    days = cert_info["days_remaining"]
    expired = cert_info["is_expired"]
    border_style = _validity_style(days, expired)

    title = Text()
    title.append(
        "  Certificate {0} of {1}  ".format(index, total),
        style="bold white",
    )
    if cert_info["is_self_signed"]:
        title.append("[Self-Signed] ", style="italic yellow")
    if cert_info["is_ca"]:
        title.append("[CA] ", style="italic cyan")

    return Panel(
        _build_cert_table(cert_info),
        title=title,
        border_style=border_style,
        box=box.ROUNDED,
        padding=(0, 1),
    )


def display_certs(certs, warnings, paging=False):
    # type: (List[dict], List[str], bool) -> None
    """Print certificate information to the terminal.

    Args:
        certs: list of cert info dicts from analyse_certificate()
        warnings: list of warning/error strings to display
        paging: if True, display output via a pager (like 'more')
    """
    console = Console()

    def _render():
        # type: () -> None
        console.print()
        console.print(
            Panel(
                Text(
                    "{0} certificate{1} found".format(
                        len(certs), "s" if len(certs) != 1 else ""
                    ),
                    style="bold white",
                ),
                title="[bold cyan]cert-piper  \u2022  Certificate Analysis[/bold cyan]",
                border_style="cyan",
                box=box.DOUBLE,
            )
        )

        total = len(certs)
        for i, cert_info in enumerate(certs, start=1):
            console.print(_cert_panel(cert_info, i, total))

        for warning in warnings:
            console.print("[red]  Warning: {0}[/red]".format(warning))

        console.print()

    if paging:
        with console.pager():
            _render()
    else:
        _render()
