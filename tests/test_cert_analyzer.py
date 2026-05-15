"""Tests for cert_piper.cert_analyzer."""

import pytest

from cert_piper.cert_analyzer import (
    analyse_certificate,
    extract_certs_from_input,
    extract_pem_certs,
)


# ---------------------------------------------------------------------------
# extract_pem_certs
# ---------------------------------------------------------------------------


class TestExtractPemCerts:
    def test_single_cert(self, leaf_pem):
        certs = extract_pem_certs(leaf_pem)
        assert len(certs) == 1
        assert "BEGIN CERTIFICATE" in certs[0]

    def test_bundle_of_two(self, bundle_pem):
        certs = extract_pem_certs(bundle_pem)
        assert len(certs) == 2

    def test_no_certs(self):
        assert extract_pem_certs("just some text, no certs here") == []

    def test_cert_with_surrounding_text(self, leaf_pem):
        text = "some prefix\n" + leaf_pem + "\nsome suffix"
        certs = extract_pem_certs(text)
        assert len(certs) == 1


# ---------------------------------------------------------------------------
# extract_certs_from_input – PEM input
# ---------------------------------------------------------------------------


class TestExtractCertsFromInputPem:
    def test_single_pem(self, leaf_pem):
        certs, warnings, detected_b64 = extract_certs_from_input(leaf_pem)
        assert len(certs) == 1
        assert warnings == []
        assert detected_b64 is False

    def test_bundle_pem(self, bundle_pem):
        certs, warnings, detected_b64 = extract_certs_from_input(bundle_pem)
        assert len(certs) == 2
        assert warnings == []
        assert detected_b64 is False

    def test_pem_with_noise(self, leaf_pem):
        raw = "some extra text\n" + leaf_pem + "\nmore text at end"
        certs, warnings, detected_b64 = extract_certs_from_input(raw)
        assert len(certs) == 1
        assert detected_b64 is False

    def test_no_certs_returns_empty(self):
        certs, warnings, detected_b64 = extract_certs_from_input("not a cert")
        assert certs == []


# ---------------------------------------------------------------------------
# extract_certs_from_input – base64 input
# ---------------------------------------------------------------------------


class TestExtractCertsFromInputBase64:
    def test_base64_pem(self, leaf_b64_pem):
        """Base64-encoded PEM should be decoded and parsed."""
        certs, warnings, detected_b64 = extract_certs_from_input(leaf_b64_pem)
        assert len(certs) == 1
        assert detected_b64 is True
        assert warnings == []

    def test_base64_der(self, leaf_b64_der):
        """Base64-encoded DER should be decoded and parsed."""
        certs, warnings, detected_b64 = extract_certs_from_input(leaf_b64_der)
        assert len(certs) == 1
        assert detected_b64 is True
        assert warnings == []

    def test_base64_bundle(self, bundle_b64):
        """Base64-encoded PEM bundle should yield two certs."""
        certs, warnings, detected_b64 = extract_certs_from_input(bundle_b64)
        assert len(certs) == 2
        assert detected_b64 is True


# ---------------------------------------------------------------------------
# analyse_certificate – RSA leaf
# ---------------------------------------------------------------------------


class TestAnalyseCertificateLeaf:
    @pytest.fixture(autouse=True)
    def setup(self, leaf_pem):
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert_obj = x509.load_pem_x509_certificate(leaf_pem.encode(), default_backend())
        self.info = analyse_certificate(cert_obj)

    def test_subject_cn(self):
        cn_values = [v for k, v in self.info["subject"] if k == "CN"]
        assert cn_values == ["test.example.com"]

    def test_subject_org(self):
        org_values = [v for k, v in self.info["subject"] if k == "O"]
        assert org_values == ["Test Corp Ltd"]

    def test_key_type_rsa(self):
        assert self.info["key_type"] == "RSA"
        assert self.info["key_bits"] == 2048

    def test_signature_algorithm(self):
        assert "sha256" in self.info["signature_algorithm"].lower()

    def test_is_not_ca(self):
        assert self.info["is_ca"] is False

    def test_sans_present(self):
        assert len(self.info["sans"]) == 3
        san_types = [t for t, _ in self.info["sans"]]
        assert "DNS" in san_types
        assert "IP" in san_types

    def test_ocsp_url(self):
        assert self.info["ocsp_urls"] == ["http://ocsp.example.com"]

    def test_ca_issuers_url(self):
        assert self.info["ca_issuer_urls"] == ["http://ca.example.com/ca.crt"]

    def test_crl_url(self):
        assert self.info["crl_urls"] == ["http://crl.example.com/crl.pem"]

    def test_ocsp_must_staple(self):
        assert self.info["ocsp_must_staple"] is True

    def test_key_usage(self):
        assert "Digital Signature" in self.info["key_usage"]
        assert "Key Encipherment" in self.info["key_usage"]

    def test_extended_key_usage(self):
        assert "TLS Web Server Authentication" in self.info["extended_key_usage"]
        assert "TLS Web Client Authentication" in self.info["extended_key_usage"]

    def test_fingerprints(self):
        # SHA-256: 32 bytes = 95 chars in colon-hex
        assert len(self.info["fingerprint_sha256"]) == 95
        # SHA-1: 20 bytes = 59 chars
        assert len(self.info["fingerprint_sha1"]) == 59

    def test_serial_hex(self):
        assert self.info["serial"] == "01:02:03:04:05:06:07"

    def test_validity_fields_present(self):
        assert self.info["not_before"] is not None
        assert self.info["not_after"] is not None
        assert isinstance(self.info["days_remaining"], int)


# ---------------------------------------------------------------------------
# analyse_certificate – CA cert
# ---------------------------------------------------------------------------


class TestAnalyseCertificateCA:
    @pytest.fixture(autouse=True)
    def setup(self, ca_pem):
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert_obj = x509.load_pem_x509_certificate(ca_pem.encode(), default_backend())
        self.info = analyse_certificate(cert_obj)

    def test_is_ca(self):
        assert self.info["is_ca"] is True

    def test_is_self_signed(self):
        assert self.info["is_self_signed"] is True

    def test_no_sans(self):
        assert self.info["sans"] == []

    def test_no_ocsp_must_staple(self):
        assert self.info["ocsp_must_staple"] is False


# ---------------------------------------------------------------------------
# analyse_certificate – EC cert
# ---------------------------------------------------------------------------


class TestAnalyseCertificateEC:
    @pytest.fixture(autouse=True)
    def setup(self, ec_pem):
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert_obj = x509.load_pem_x509_certificate(ec_pem.encode(), default_backend())
        self.info = analyse_certificate(cert_obj)

    def test_key_type_ec(self):
        assert "EC" in self.info["key_type"]

    def test_key_bits(self):
        assert self.info["key_bits"] == 256


# ---------------------------------------------------------------------------
# analyse_certificate – expired cert
# ---------------------------------------------------------------------------


class TestAnalyseCertificateExpired:
    @pytest.fixture(autouse=True)
    def setup(self, expired_pem):
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert_obj = x509.load_pem_x509_certificate(expired_pem.encode(), default_backend())
        self.info = analyse_certificate(cert_obj)

    def test_is_expired(self):
        assert self.info["is_expired"] is True

    def test_negative_days_remaining(self):
        assert self.info["days_remaining"] < 0
