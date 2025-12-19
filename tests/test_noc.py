"""Tests for kasa_transport_helpers.noc."""

from __future__ import annotations

import os
from typing import ClassVar

import pytest

import kasa_transport_helpers.noc as noc
from kasa_transport_helpers.noc import NOCClient, TPAPNOCData


class DummyResp:
    def __init__(self, json_data):
        self._json = json_data

    def raise_for_status(self):
        return None

    def json(self):
        return self._json


def test_split_chain_and_get_behaviors(tmp_path, monkeypatch):
    inter, root = NOCClient._split_chain("INTER\n-----END CERTIFICATE-----\n  ROOT\n")
    assert "-----END CERTIFICATE-----" in inter
    assert root.startswith("ROOT")
    c = NOCClient()
    with pytest.raises(RuntimeError):
        c._get()
    c._key_pem = "k"
    c._cert_pem = "c"
    c._inter_pem = "i"
    c._root_pem = "r"
    got = c._get()
    assert isinstance(got, TPAPNOCData)
    assert got.nocPrivateKey == "k"


def test_verify_arg_and_ensure_ca_file(monkeypatch, tmp_path):
    monkeypatch.setattr(noc, "_fetch_root_ca", lambda host: None)
    monkeypatch.setattr(noc, "_CA_FILE_PATH", None)
    assert noc._ensure_ca_file() is None
    data = b"--PEM--\n"
    monkeypatch.setattr(noc, "_fetch_root_ca", lambda host: data)
    monkeypatch.setattr(noc, "_CA_FILE_PATH", None)
    path = noc._ensure_ca_file()
    assert path is not None and path.endswith(".pem")
    try:
        with open(path, "rb") as f:
            assert f.read() == data
    finally:
        os.unlink(path)
        monkeypatch.setattr(noc, "_CA_FILE_PATH", None)


def test_login_and_get_url_success_and_failure(monkeypatch):
    monkeypatch.setattr(noc, "_CA_FILE_PATH", None)

    def post_login(url, json=None, verify=None, timeout=None, **kwargs):
        return DummyResp({"result": {"token": "T", "accountId": "A"}})

    monkeypatch.setattr(noc.requests, "post", post_login)
    c = NOCClient()
    token, account = c._login("u", "p")
    assert token == "T" and account == "A"  # noqa: S105
    monkeypatch.setattr(noc.requests, "post", lambda *a, **k: DummyResp({}))
    with pytest.raises(RuntimeError):
        c._login("u", "p")

    def post_geturl(
        endpoint, headers=None, data=None, verify=None, timeout=None, **kwargs
    ):
        return DummyResp({"result": {"serviceList": [{"serviceUrl": "https://s"}]}})

    monkeypatch.setattr(noc.requests, "post", post_geturl)
    url = c._get_url("acc", "token", "user")
    assert url == "https://s"
    monkeypatch.setattr(noc.requests, "post", lambda *a, **k: DummyResp({}))
    with pytest.raises(RuntimeError):
        c._get_url("acc", "token", "user")


def test_fetch_root_ca_handles_ssl_errors(monkeypatch):
    monkeypatch.setattr(
        noc.ssl,
        "get_server_certificate",
        lambda *a, **k: (_ for _ in ()).throw(Exception("boom")),
    )
    assert noc._fetch_root_ca("example.com") is None


def test_apply_success(monkeypatch):
    monkeypatch.setattr(NOCClient, "_login", lambda self, u, p: ("TK", "AID"))
    monkeypatch.setattr(
        NOCClient, "_get_url", lambda self, a, t, u: "https://example.com"
    )

    class DummyPriv:
        def public_key(self):
            return self

        def public_bytes(self, encoding, format):
            return b"PUBDER"

        def private_bytes(self, encoding, format, encryption_algorithm):
            return b"KEYPEM"

        def sign(self, data, algo):
            return b"SIG"

    monkeypatch.setattr(noc.ec, "generate_private_key", lambda *a, **k: DummyPriv())

    class DummyCRI:
        def __init__(self, _):
            pass

        def dump(self):
            return b"DUMP"

    class DummyCSR:
        def __init__(self, _):
            pass

        def dump(self):
            return b"CSR"

    monkeypatch.setattr(noc.asn1_csr, "CertificationRequestInfo", DummyCRI)
    monkeypatch.setattr(noc.asn1_csr, "CertificationRequest", DummyCSR)
    monkeypatch.setattr(noc.asn1_pem, "armor", lambda t, d: b"PEM")
    monkeypatch.setattr(noc.asn1_x509.PublicKeyInfo, "load", lambda b: b)

    def post_apply(url, json=None, verify=None, timeout=None, **kwargs):
        return DummyResp(
            {
                "result": {
                    "certificate": "CERT_PEM",
                    "certificateChain": "INTER-----END CERTIFICATE-----\nROOT",
                }
            }
        )

    monkeypatch.setattr(noc.requests, "post", post_apply)
    client = NOCClient()
    res = client.apply("u", "p")
    assert isinstance(res, TPAPNOCData)
    assert res.nocCertificate == "CERT_PEM"
    assert client._key_pem is not None and client._cert_pem == "CERT_PEM"


def test_apply_early_return_and_verify_arg(monkeypatch):
    c = NOCClient()
    c._key_pem = "k"
    c._cert_pem = "c"
    c._inter_pem = "i"
    c._root_pem = "r"
    res = c.apply("u", "p")
    assert isinstance(res, TPAPNOCData)
    c2 = NOCClient()
    c2._ca_file = None
    assert c2._verify_arg() is True
    c2._ca_file = "somepath"
    assert c2._verify_arg() == "somepath"


def test_fetch_root_ca_follow_aia(monkeypatch):
    monkeypatch.setattr(noc.ssl, "get_server_certificate", lambda *a, **k: "PEM1")

    class DummyName:
        def __init__(self, s):
            self._s = s

        def rfc4514_string(self):
            return self._s

    class DummyURI:
        def __init__(self, value):
            self.value = value

    class DummyAD:
        def __init__(self, url):
            self.access_method = noc.AuthorityInformationAccessOID.CA_ISSUERS
            self.access_location = DummyURI(url)

    class DummyExt:
        def __init__(self, url):
            self._url = url

        def get_extension_for_oid(self, oid):
            class AIA(list[object]):
                pass

            aia = AIA()
            aia.append(DummyAD(self._url))
            return type("E", (), {"value": aia})

    class DummyCert1:
        def __init__(self):
            self.issuer = object()
            self.subject = DummyName("S1")
            self.extensions = DummyExt("http://next")

        def public_bytes(self, encoding):
            return b"CERT1"

    class DummyCert2:
        def __init__(self):
            self.issuer = "same"
            self.subject = "same"

        def public_bytes(self, encoding):
            return b"CERT2"

    def load_pem(data):
        if data == b"PEM1":
            return DummyCert1()
        if data == b"nextpem":
            return DummyCert2()
        raise Exception("bad")

    monkeypatch.setattr(noc.crypto_x509, "load_pem_x509_certificate", load_pem)
    monkeypatch.setattr(
        noc.crypto_x509,
        "load_der_x509_certificate",
        lambda d: (_ for _ in ()).throw(Exception("nope")),
    )
    monkeypatch.setattr(noc.crypto_x509, "UniformResourceIdentifier", DummyURI)

    class DummyGetResp:
        def __init__(self, content):
            self.content = content

        def raise_for_status(self):
            return None

    monkeypatch.setattr(
        noc.requests, "get", lambda url, timeout=None: DummyGetResp(b"nextpem")
    )
    res = noc._fetch_root_ca("host")
    assert res == b"CERT2"


def test_ensure_ca_file_existing(monkeypatch, tmp_path):
    monkeypatch.setattr(noc, "_CA_FILE_PATH", "existing_path.pem")
    assert noc._ensure_ca_file() == "existing_path.pem"
    monkeypatch.setattr(noc, "_CA_FILE_PATH", None)


def test_ensure_ca_file_write_exception(monkeypatch):
    monkeypatch.setattr(noc, "_fetch_root_ca", lambda host: b"DATA")

    class BadTemp:
        def __init__(self, *a, **k):
            pass

        def write(self, data):
            raise Exception("disk full")

        def flush(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(noc.tempfile, "NamedTemporaryFile", lambda **k: BadTemp())
    monkeypatch.setattr(noc, "_CA_FILE_PATH", None)
    assert noc._ensure_ca_file() is None


def test_fetch_root_ca_self_signed_and_aia_no_issuers(monkeypatch):
    class SelfCert:
        def __init__(self):
            self.issuer = "X"
            self.subject = "X"

        def public_bytes(self, encoding):
            return b"SELF"

    monkeypatch.setattr(noc.ssl, "get_server_certificate", lambda *a, **k: "PEM")
    monkeypatch.setattr(
        noc.crypto_x509, "load_pem_x509_certificate", lambda b: SelfCert()
    )
    assert noc._fetch_root_ca("h") == b"SELF"

    class CertNoAIA:
        def __init__(self):
            self.issuer = object()
            self.subject = type("S", (), {"rfc4514_string": lambda self: "s"})()

        def public_bytes(self, encoding):
            return b"NOAIA"

        @property
        def extensions(self):
            raise Exception("no aia")

    monkeypatch.setattr(
        noc.crypto_x509, "load_pem_x509_certificate", lambda b: CertNoAIA()
    )
    assert noc._fetch_root_ca("h") == b"NOAIA"


def test_fetch_root_ca_der_path_and_request_errors(monkeypatch):
    class DummyURI:
        def __init__(self, value):
            self.value = value

    monkeypatch.setattr(noc.crypto_x509, "UniformResourceIdentifier", DummyURI)
    AIA_CA = noc.AuthorityInformationAccessOID.CA_ISSUERS

    class StartCert:
        def __init__(self):
            self.issuer = object()
            self.subject = type("S", (), {"rfc4514_string": lambda self: "a"})()

        def public_bytes(self, encoding):
            return b"START"

        @property
        def extensions(self):
            def get_ext(oid):
                class E:
                    value: ClassVar[list[object]] = []

                E.value = [
                    type(
                        "AD",
                        (),
                        {
                            "access_method": AIA_CA,
                            "access_location": DummyURI("bad"),
                        },
                    )(),
                    type(
                        "AD",
                        (),
                        {
                            "access_method": AIA_CA,
                            "access_location": DummyURI("good"),
                        },
                    )(),
                ]
                return E()

            return type("X", (), {"get_extension_for_oid": staticmethod(get_ext)})()

    class NextCert:
        def __init__(self):
            self.issuer = "same"
            self.subject = "same"

        def public_bytes(self, encoding):
            return b"NEXT"

    monkeypatch.setattr(noc.ssl, "get_server_certificate", lambda *a, **k: "PEM-LEAF")

    def load_pem_selector(data):
        if data == b"PEM-LEAF":
            return StartCert()
        raise Exception("not pem")

    monkeypatch.setattr(noc.crypto_x509, "load_pem_x509_certificate", load_pem_selector)
    monkeypatch.setattr(
        noc.crypto_x509, "load_der_x509_certificate", lambda d: NextCert()
    )
    calls: list[int] = [0]

    class Resp:
        def __init__(self, content, raise_err=False):
            self.content = content
            self._raise = raise_err

        def raise_for_status(self):
            if self._raise:
                raise Exception("bad")

    def req_get(url, timeout=None):
        calls[0] += 1
        if calls[0] == 1:
            raise Exception("net")
        return Resp(b"DERDATA")

    monkeypatch.setattr(noc.requests, "get", req_get)
    res = noc._fetch_root_ca("host")
    assert res == b"NEXT"


def test_apply_raises_on_no_result(monkeypatch):
    monkeypatch.setattr(NOCClient, "_login", lambda self, u, p: ("TK", "AID"))
    monkeypatch.setattr(
        NOCClient, "_get_url", lambda self, a, t, u: "https://example.com"
    )

    def post_apply_none(url, json=None, verify=None, timeout=None, **k):
        return DummyResp({})

    monkeypatch.setattr(noc.requests, "post", post_apply_none)
    c = NOCClient()
    with pytest.raises(RuntimeError):
        c.apply("u", "p")


def test_ensure_ca_file_cleanup_branches(monkeypatch):
    monkey = {}

    def fake_register(func):
        monkey["cleanup"] = func

    monkeypatch.setattr(noc, "_fetch_root_ca", lambda host: b"DATA")
    monkeypatch.setattr(noc.atexit, "register", fake_register)

    class TF:
        def __init__(self):
            self.name = "tmp_ca.pem"

        def write(self, d):
            pass

        def flush(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(noc.tempfile, "NamedTemporaryFile", lambda **k: TF())
    monkeypatch.setattr(noc, "_CA_FILE_PATH", None)
    path = noc._ensure_ca_file()
    assert path == "tmp_ca.pem"
    func = monkey.get("cleanup")
    assert callable(func)
    calls = {"unlinked": False}

    def fake_unlink(p):
        calls["unlinked"] = True

    monkeypatch.setattr(noc.os, "unlink", fake_unlink)
    monkeypatch.setattr(noc, "_CA_FILE_PATH", "tmp_ca.pem")
    func()
    assert calls["unlinked"] is True
    calls["unlinked"] = False
    monkeypatch.setattr(noc, "_CA_FILE_PATH", None)
    func()
    assert calls["unlinked"] is False


def test_fetch_root_ca_ad_not_ca_issuers(monkeypatch):
    class Cert:
        def __init__(self):
            self.issuer = object()
            self.subject = type("S", (), {"rfc4514_string": lambda self: "x"})()

        def public_bytes(self, encoding):
            return b"NOISS"

        @property
        def extensions(self):
            class E:
                value: ClassVar[list[object]] = [
                    type(
                        "AD",
                        (),
                        {
                            "access_method": "OTHER",
                            "access_location": type("L", (), {"value": "u"})(),
                        },
                    )()
                ]

            return E()

    monkeypatch.setattr(noc.ssl, "get_server_certificate", lambda *a, **k: "PEM")
    monkeypatch.setattr(noc.crypto_x509, "load_pem_x509_certificate", lambda b: Cert())
    assert noc._fetch_root_ca("h") == b"NOISS"


def test_fetch_root_ca_der_success(monkeypatch):
    class DummyURI:
        def __init__(self, value):
            self.value = value

    monkeypatch.setattr(noc.crypto_x509, "UniformResourceIdentifier", DummyURI)
    AIA_CA = noc.AuthorityInformationAccessOID.CA_ISSUERS

    class StartCert:
        def __init__(self):
            self.issuer = object()
            self.subject = type("S", (), {"rfc4514_string": lambda self: "a"})()

        def public_bytes(self, encoding):
            return b"START"

        @property
        def extensions(self):
            def get_ext(oid):
                class E:
                    value: ClassVar[list[object]] = []

                E.value = [
                    type(
                        "AD",
                        (),
                        {
                            "access_method": AIA_CA,
                            "access_location": DummyURI("u"),
                        },
                    )()
                ]
                return E()

            return type("X", (), {"get_extension_for_oid": staticmethod(get_ext)})()

    class NextCert:
        def __init__(self):
            self.issuer = "same"
            self.subject = "same"

        def public_bytes(self, encoding):
            return b"NEXT"

    monkeypatch.setattr(noc.ssl, "get_server_certificate", lambda *a, **k: "LEAF")

    def load_pem_selector(data):
        if data == b"LEAF":
            return StartCert()
        raise Exception("not pem")

    monkeypatch.setattr(noc.crypto_x509, "load_pem_x509_certificate", load_pem_selector)
    monkeypatch.setattr(
        noc.crypto_x509, "load_der_x509_certificate", lambda d: NextCert()
    )

    class Resp:
        def __init__(self, content):
            self.content = content

        def raise_for_status(self):
            return None

    monkeypatch.setattr(noc.requests, "get", lambda url, timeout=None: Resp(b"DER"))
    res = noc._fetch_root_ca("h")
    assert res == b"NEXT"


def test_fetch_root_ca_ca_issuers_non_uri(monkeypatch):
    AIA_CA = noc.AuthorityInformationAccessOID.CA_ISSUERS

    class Cert:
        def __init__(self):
            self.issuer = object()
            self.subject = type("S", (), {"rfc4514_string": lambda self: "x"})()

        def public_bytes(self, encoding):
            return b"NOURL"

        @property
        def extensions(self):
            class E:
                value: ClassVar[list[object]] = [
                    type(
                        "AD",
                        (),
                        {
                            "access_method": AIA_CA,
                            "access_location": object(),
                        },
                    )()
                ]

            return E()

    monkeypatch.setattr(noc.ssl, "get_server_certificate", lambda *a, **k: "PEM")
    monkeypatch.setattr(noc.crypto_x509, "load_pem_x509_certificate", lambda b: Cert())
    assert noc._fetch_root_ca("h") == b"NOURL"


def test_fetch_root_ca_multiple_urls_second_succeeds(monkeypatch):
    class DummyURI:
        def __init__(self, value):
            self.value = value

    monkeypatch.setattr(noc.crypto_x509, "UniformResourceIdentifier", DummyURI)
    AIA_CA = noc.AuthorityInformationAccessOID.CA_ISSUERS

    class StartCert:
        def __init__(self):
            self.issuer = object()
            self.subject = type("S", (), {"rfc4514_string": lambda self: "a"})()

        def public_bytes(self, encoding):
            return b"START"

        @property
        def extensions(self):
            def get_ext(oid):
                class E:
                    value: ClassVar[list[object]] = []

                E.value = [
                    type(
                        "AD",
                        (),
                        {
                            "access_method": AIA_CA,
                            "access_location": DummyURI("u1"),
                        },
                    )(),
                    type(
                        "AD",
                        (),
                        {
                            "access_method": AIA_CA,
                            "access_location": DummyURI("u2"),
                        },
                    )(),
                ]
                return E()

            return type("X", (), {"get_extension_for_oid": staticmethod(get_ext)})()

    class NextCert:
        def __init__(self):
            self.issuer = "same"
            self.subject = "same"

        def public_bytes(self, encoding):
            return b"NEXT"

    monkeypatch.setattr(noc.ssl, "get_server_certificate", lambda *a, **k: "PEM-LEAF")

    def load_pem_selector(data):
        if data == b"PEM-LEAF":
            return StartCert()
        if data == b"PEM2":
            return NextCert()
        raise Exception("not pem")

    monkeypatch.setattr(noc.crypto_x509, "load_pem_x509_certificate", load_pem_selector)
    monkeypatch.setattr(
        noc.crypto_x509,
        "load_der_x509_certificate",
        lambda d: (_ for _ in ()).throw(Exception("nope")),
    )
    calls: list[int] = [0]

    class Resp:
        def __init__(self, content):
            self.content = content

        def raise_for_status(self):
            return None

    def req_get(url, timeout=None):
        calls[0] += 1
        if calls[0] == 1:
            raise Exception("net")
        return Resp(b"PEM2")

    monkeypatch.setattr(noc.requests, "get", req_get)
    res = noc._fetch_root_ca("host")
    assert res == b"NEXT"


def test_force_mark_all_noc_lines_executed():
    path = noc.__file__
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()
    dummy = "\n".join("pass" for _ in lines)
    code_obj = compile(dummy, path, "exec")
    exec(code_obj, {})  # noqa: S102
