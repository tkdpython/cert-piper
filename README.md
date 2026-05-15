# cert-piper

A command-line tool for displaying X.509 certificate information from piped input.

Pipe any PEM certificate file (or a base64-encoded certificate) into `cert-piper` and get a rich, colour-coded summary of every certificate in the stream — including validity, key details, SANs, fingerprints, and more.

---

## Features

- **Pipe-friendly** — reads from stdin, works naturally with `cat`, `curl`, `openssl`, etc.
- **Batch support** — handles PEM bundles with multiple certificates in a single stream
- **Base64 detection** — automatically detects and decodes base64-encoded PEM or DER input
- **Rich output** — colour-coded expiry status, structured sections, emojis
- **`--paging` option** — scroll through long output with a built-in pager
- **Semver versioning** — published to PyPI from git tags via GitHub Actions

---

## Installation

```bash
pip install cert-piper
```

Or install from source:

```bash
git clone https://github.com/tkdpython/cert-piper.git
cd cert-piper
pip install -e .
```

---

## Usage

```bash
# Single certificate
cat mycert.pem | cert-piper

# Run as a Python module
cat mycert.pem | python3 -m cert_piper

# PEM bundle (multiple certificates in one file)
cat bundle.pem | cert-piper

# Base64-encoded certificate (auto-detected and decoded)
cat encoded.b64 | cert-piper

# Paged output for large bundles
cat bundle.pem | cert-piper --paging

# Fetch a remote certificate via openssl
openssl s_client -connect example.com:443 -showcerts </dev/null 2>/dev/null | cert-piper

# Show version
cert-piper --version
```

---

## What It Shows

For each certificate in the stream:

| Section | Details |
|---|---|
| **Subject** | Common Name, Organisation, Country, etc. |
| **Issuer** | Same fields as Subject |
| **Validity** | Not Before / Not After, days remaining, expiry status (🟢 valid / 🟡 expiring / 🔴 expired) |
| **Public Key** | Algorithm (RSA / EC / Ed25519 / …), key size, signature algorithm |
| **SANs** | DNS names, IP addresses, email addresses, URIs |
| **Key Usage** | Key Usage and Extended Key Usage flags |
| **OCSP / Revocation** | OCSP URLs, CA Issuers URLs, CRL Distribution Points, OCSP Must-Staple |
| **Fingerprints** | SHA-256 and SHA-1 |
| **Additional Details** | Serial number, self-signed status, CA flag, path length, Subject/Authority Key IDs |

---

## Base64 Detection

If no PEM `-----BEGIN CERTIFICATE-----` headers are found in the input, `cert-piper` will automatically attempt to base64-decode the input and retry. This handles:

- PEM data that has been base64-encoded (e.g. copied from a Kubernetes secret)
- Raw DER certificate bytes that have been base64-encoded

When base64 decoding is applied a notice is printed:

```
(base64-encoded input detected and decoded)
```

---

## Publishing

Releases are published to [PyPI](https://pypi.org/project/cert-piper/) automatically when a semver git tag is pushed:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The version is derived from the git tag via `setuptools-scm`.
