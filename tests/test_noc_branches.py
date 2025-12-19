import types

from kasa_transport_helpers import noc


def make_fake_cert(public_bytes_value: bytes, aia_value):
    class FakeExts:
        def get_extension_for_oid(self, oid):
            class Val:
                value = aia_value

            return Val()

    class FakeCert:
        issuer = object()
        subject = types.SimpleNamespace(rfc4514_string=lambda: "subj")

        def __init__(self):
            self.extensions = FakeExts()

        def public_bytes(self, encoding):
            return public_bytes_value

    return FakeCert()


def test_fetch_root_ca_aia_non_ca_issuers(monkeypatch):
    # AIA entry with access_method not equal to CA_ISSUERS -> urls stays empty
    ad = types.SimpleNamespace(access_method=object(), access_location=object())
    fake_cert = make_fake_cert(b"PEM1", [ad])

    monkeypatch.setattr(noc.ssl, "get_server_certificate", lambda *a, **k: "pem")
    monkeypatch.setattr(noc.crypto_x509, "load_pem_x509_certificate", lambda b: fake_cert)

    res = noc._fetch_root_ca("host")
    assert res == b"PEM1"


def test_fetch_root_ca_aia_access_location_not_uri(monkeypatch):
    # access_method is CA_ISSUERS but access_location is not a UniformResourceIdentifier
    ad = types.SimpleNamespace(access_method=noc.AuthorityInformationAccessOID.CA_ISSUERS, access_location=object())
    fake_cert = make_fake_cert(b"PEM2", [ad])

    monkeypatch.setattr(noc.ssl, "get_server_certificate", lambda *a, **k: "pem")
    monkeypatch.setattr(noc.crypto_x509, "load_pem_x509_certificate", lambda b: fake_cert)

    res = noc._fetch_root_ca("host")
    assert res == b"PEM2"


def test_fetch_root_ca_url_fetch_parse_fail(monkeypatch):
    # access_location appears as URI, but fetched data cannot be parsed as PEM or DER
    class URI:
        def __init__(self, value):
            self.value = value

    ad = types.SimpleNamespace(access_method=noc.AuthorityInformationAccessOID.CA_ISSUERS, access_location=URI("http://x"))
    fake_cert = make_fake_cert(b"PEM3", [ad])

    monkeypatch.setattr(noc.ssl, "get_server_certificate", lambda *a, **k: "pem")
    monkeypatch.setattr(noc.crypto_x509, "load_pem_x509_certificate", lambda b: fake_cert)

    # Make isinstance(loc, UniformResourceIdentifier) succeed by patching the class
    monkeypatch.setattr(noc.crypto_x509, "UniformResourceIdentifier", URI)

    class FakeResp:
        content = b"bad"

        def raise_for_status(self):
            return None

    monkeypatch.setattr(noc.requests, "get", lambda url, timeout: FakeResp())

    # Make leaf parse succeed but fetched data parsing fail
    def load_pem(data):
        if data == b"pem":
            return fake_cert
        raise Exception("bad pem")

    def load_der(data):
        raise Exception("bad der")

    monkeypatch.setattr(noc.crypto_x509, "load_pem_x509_certificate", load_pem)
    monkeypatch.setattr(noc.crypto_x509, "load_der_x509_certificate", load_der)

    res = noc._fetch_root_ca("host")
    assert res == b"PEM3"
