"""NOC client for TPAP Transport."""

from __future__ import annotations

import atexit
import base64
import hashlib
import hmac
import json
import logging
import os
import ssl
import tempfile
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

import requests
from asn1crypto import core as asn1_core
from asn1crypto import csr as asn1_csr
from asn1crypto import pem as asn1_pem
from asn1crypto import x509 as asn1_x509
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

_LOGGER = logging.getLogger(__name__)
_ACCESS_KEY = "4d11b6b9d5ea4d19a829adbb9714b057"
_SECRET_KEY = "6ed7d97f3e73467f8a5bab90b577ba4c"  # noqa: S105
_CA_FILE_PATH_LOCK = threading.Lock()
_CA_FILE_PATH: str | None = None


def _ensure_ca_file() -> str | None:
    """Attempt to fetch the server's root CA certificate chain."""
    global _CA_FILE_PATH
    if _CA_FILE_PATH:
        return _CA_FILE_PATH
    with _CA_FILE_PATH_LOCK:
        if _CA_FILE_PATH is not None:
            return _CA_FILE_PATH
        try:
            data = _fetch_root_ca("n-wap.i.tplinkcloud.com")
            if not data:
                _LOGGER.debug(
                    "kasa_transport_helpers: could not fetch root CA from host"
                )
                _CA_FILE_PATH = None
                return None
            tf = tempfile.NamedTemporaryFile(
                delete=False, prefix="kasa_root_ca_", suffix=".pem"
            )
            tf.write(data)
            tf.flush()
            tf.close()
            _CA_FILE_PATH = tf.name

            def _cleanup() -> None:
                try:
                    if _CA_FILE_PATH:
                        os.unlink(_CA_FILE_PATH)
                except Exception as exc:
                    _LOGGER.debug(
                        "kasa_transport_helpers: cleanup unlink failed: %s", exc
                    )

            atexit.register(_cleanup)
            _LOGGER.debug(
                "kasa_transport_helpers: fetched root CA and wrote to %s", _CA_FILE_PATH
            )
            return _CA_FILE_PATH
        except Exception as exc:
            _LOGGER.debug(
                "kasa_transport_helpers: unable to fetch/write root CA: %s", exc
            )
            _CA_FILE_PATH = None
            return None


def _fetch_root_ca(hostname: str) -> bytes | None:
    """Fetch the server certificate and follow AIA CA Issuers links."""
    try:
        leaf_pem = ssl.get_server_certificate((hostname, 443))
        try:
            cert = crypto_x509.load_pem_x509_certificate(leaf_pem.encode())
        except Exception:
            _LOGGER.debug("kasa_transport_helpers: failed to parse leaf cert PEM")
            return None
        visited = set()
        while True:
            if cert.issuer == cert.subject:
                return cert.public_bytes(serialization.Encoding.PEM)
            subj_str = cert.subject.rfc4514_string()
            if subj_str in visited:
                return cert.public_bytes(serialization.Encoding.PEM)
            visited.add(subj_str)
            urls = []
            try:
                aia = cert.extensions.get_extension_for_oid(
                    ExtensionOID.AUTHORITY_INFORMATION_ACCESS
                ).value
                for ad in aia:
                    if ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                        loc = ad.access_location
                        if isinstance(loc, crypto_x509.UniformResourceIdentifier):
                            urls.append(loc.value)
            except Exception:
                urls = []
            if not urls:
                return cert.public_bytes(serialization.Encoding.PEM)
            next_cert = None
            for url in urls:
                try:
                    r = requests.get(url, timeout=10.0)
                    r.raise_for_status()
                    data = r.content
                    try:
                        next_cert = crypto_x509.load_pem_x509_certificate(data)
                    except Exception:
                        try:
                            next_cert = crypto_x509.load_der_x509_certificate(data)
                        except Exception:
                            next_cert = None
                    if next_cert:
                        break
                except Exception as exc:
                    _LOGGER.debug(
                        "kasa_transport_helpers: failed to fetch AIA url %s: %s",
                        url,
                        exc,
                    )
                    continue
            if not next_cert:
                return cert.public_bytes(serialization.Encoding.PEM)
            cert = next_cert
    except Exception as exc:
        _LOGGER.debug("kasa_transport_helpers: _fetch_root_ca failed: %s", exc)
        return None


class NOCClient:
    """Client to fetch App NOC materials from TP-Link Cloud."""

    def __init__(self) -> None:
        self._key_pem: str | None = None
        self._cert_pem: str | None = None
        self._inter_pem: str | None = None
        self._root_pem: str | None = None
        self._ca_file: str | None = _ensure_ca_file()

    def _get(self) -> TPAPNOCData:
        if not (
            self._key_pem and self._cert_pem and self._inter_pem and self._root_pem
        ):
            raise RuntimeError("No NOC materials available.")
        return TPAPNOCData(
            nocPrivateKey=self._key_pem,
            nocCertificate=self._cert_pem,
            nocIntermediateCertificate=self._inter_pem,
            nocRootCertificate=self._root_pem,
        )

    def _verify_arg(self) -> str | bool:
        return self._ca_file if self._ca_file else True

    def _login(self, username: str, password: str) -> tuple[str, str]:
        payload = {
            "method": "login",
            "params": {
                "cloudUserName": username,
                "cloudPassword": password,
                "appType": "Tapo_Android",
                "terminalUUID": "UNOC",
            },
        }
        r = requests.post(
            "https://n-wap.i.tplinkcloud.com/",
            json=payload,
            verify=self._verify_arg(),
            timeout=15.0,
        )
        r.raise_for_status()
        result = r.json().get("result")
        if not result:
            raise RuntimeError("TP-Link login returned no result")
        return result["token"], result["accountId"]

    def _get_url(self, account_id: str, token: str, username: str) -> str:
        body_obj = {
            "serviceIds": ["nbu.cvm-server-v2"],
            "accountId": account_id,
            "cloudUserName": username,
        }
        body_bytes = json.dumps(body_obj, separators=(",", ":")).encode()
        endpoint = (
            "https://n-aps1-wap.i.tplinkcloud.com/api/v2/common/getAppServiceUrlById"
        )
        path = "/api/v2/common/getAppServiceUrlById"
        md5_bytes = hashlib.md5(body_bytes).digest()  # noqa: S324
        content_md5 = base64.b64encode(md5_bytes).decode()
        timestamp = str(int(datetime.now(UTC).timestamp()))
        nonce = str(uuid.uuid4())
        message = (content_md5 + "\n" + timestamp + "\n" + nonce + "\n" + path).encode()
        signature = hmac.new(_SECRET_KEY.encode(), message, hashlib.sha1).hexdigest()
        x_auth = (
            f"Timestamp={timestamp}, Nonce={nonce}, "
            + f"AccessKey={_ACCESS_KEY}, Signature={signature}"
        )
        headers = {
            "Content-Type": "application/json",
            "Content-MD5": content_md5,
            "X-Authorization": x_auth,
            "Authorization": token,
        }
        r = requests.post(
            endpoint,
            headers=headers,
            data=body_bytes,
            verify=self._verify_arg(),
            timeout=15.0,
        )
        r.raise_for_status()
        res = r.json().get("result")
        if not res or "serviceList" not in res or not res["serviceList"]:
            raise RuntimeError("Unexpected response from getAppServiceUrlById")
        return res["serviceList"][0]["serviceUrl"]

    @staticmethod
    def _split_chain(chain_pem: str) -> tuple[str, str]:
        inter_pem, root_pem = chain_pem.split("-----END CERTIFICATE-----", 1)
        inter_pem += "-----END CERTIFICATE-----"
        root_pem = root_pem.lstrip()
        return inter_pem, root_pem

    def apply(self, username: str, password: str) -> TPAPNOCData:
        """Apply for a new NOC and cache materials. Raises RuntimeError on failure."""
        if self._key_pem and self._cert_pem and self._inter_pem and self._root_pem:
            return self._get()
        token, account_id = self._login(username, password)
        url = self._get_url(account_id, token, username)
        priv = ec.generate_private_key(ec.SECP256R1())
        pub_der = priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        subject = asn1_x509.Name.build({"organizational_unit_name": "UNOC"})
        attributes = [
            {
                "type": "1.2.840.113549.1.9.14",
                "values": [
                    asn1_x509.Extensions(
                        [
                            asn1_x509.Extension(
                                {
                                    "extn_id": "2.5.29.15",
                                    "critical": False,
                                    "extn_value": asn1_x509.KeyUsage(
                                        {"digital_signature"}
                                    ),
                                }
                            ),
                            asn1_x509.Extension(
                                {
                                    "extn_id": "2.5.29.19",
                                    "critical": False,
                                    "extn_value": asn1_x509.BasicConstraints(
                                        {"ca": False, "path_len_constraint": None}
                                    ),
                                }
                            ),
                            asn1_x509.Extension(
                                {
                                    "extn_id": "2.5.29.14",
                                    "critical": False,
                                    "extn_value": asn1_core.OctetString(
                                        hashlib.sha1(pub_der).digest()  # noqa: S324
                                    ),
                                }
                            ),
                        ]
                    )
                ],
            }
        ]
        cri = asn1_csr.CertificationRequestInfo(
            {
                "version": 0,
                "subject": subject,
                "subject_pk_info": asn1_x509.PublicKeyInfo.load(pub_der),
                "attributes": attributes,
            }
        )
        sig = priv.sign(cri.dump(), ec.ECDSA(hashes.SHA256()))
        csr = asn1_csr.CertificationRequest(
            {
                "certification_request_info": cri,
                "signature_algorithm": asn1_x509.SignedDigestAlgorithm(
                    {"algorithm": "sha256_ecdsa"}
                ),
                "signature": sig,
            }
        )
        csr_pem = asn1_pem.armor("CERTIFICATE REQUEST", csr.dump()).decode()
        key_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        endpoint = url.rstrip("/") + "/v1/certificate/noc/app/apply"
        body = {"userToken": token, "csr": csr_pem}
        r = requests.post(endpoint, json=body, verify=self._verify_arg(), timeout=15.0)
        r.raise_for_status()
        res = r.json().get("result")
        if not res:
            raise RuntimeError("TP-Link NOC apply returned no result")
        cert_pem: str = res["certificate"]
        chain_pem: str = res["certificateChain"]
        inter_pem, root_pem = self._split_chain(chain_pem)
        self._cert_pem = cert_pem
        self._key_pem = key_pem
        self._inter_pem = inter_pem
        self._root_pem = root_pem
        return self._get()


@dataclass
class TPAPNOCData:
    """Container for returned NOC materials."""

    nocPrivateKey: str
    nocCertificate: str
    nocIntermediateCertificate: str
    nocRootCertificate: str
