"""SPAKE2+ curves and curve points for TPAP Transport."""

from __future__ import annotations

from ecdsa import NIST256p, NIST384p, NIST521p
from ecdsa.curves import Curve

P256_M_HEX = (
    "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
)
P256_N_HEX = (
    "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"
)

P384_M_HEX = (
    "030ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc36f15314739074d2eb8613fceec2853"
)
P384_N_HEX = (
    "02c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb252c5490214cf9aa3f0baab4b665c10"
)

P521_M_HEX = (
    "02003f06f38131b2ba2600791e82488e8d20ab889af753a41806c5db18d37d85608cfae06b82e4a72cd744c719193562a653ea1f119eef9356907edc9b56979962d7aa"
)
P521_N_HEX = (
    "0200c7924b9ec017f3094562894336a53c50167ba8c5963876880542bc669e494b2532d76c5b53dfb349fdf69154b9e0048c58a42e8ed04cef052a3bc349d95575cd25"
)


DEFAULT_CURVES: dict[int, tuple[Curve, bytes, bytes]] = {}
for k in (1, 2, 8, 9):
    DEFAULT_CURVES[k] = (NIST256p, bytes.fromhex(P256_M_HEX), bytes.fromhex(P256_N_HEX))
for k in (3, 4):
    DEFAULT_CURVES[k] = (NIST384p, bytes.fromhex(P384_M_HEX), bytes.fromhex(P384_N_HEX))
DEFAULT_CURVES[5] = (NIST521p, bytes.fromhex(P521_M_HEX), bytes.fromhex(P521_N_HEX))


def get_curve_and_points(suite_type: int) -> tuple[Curve, bytes, bytes]:
    """Return (curve, M, N) for given SPAKE2+ suite_type."""
    try:
        curve_obj, m, n = DEFAULT_CURVES[suite_type]
    except KeyError:
        raise KeyError(f"Unsupported SPAKE2+ suite type: {suite_type}")
    return curve_obj, m, n
