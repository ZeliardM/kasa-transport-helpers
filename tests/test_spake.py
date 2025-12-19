"""Tests for kasa_transport_helpers.spake."""

from __future__ import annotations

import pytest
from ecdsa import NIST256p, NIST384p, NIST521p

import kasa_transport_helpers.spake as spake
from kasa_transport_helpers import get_curve_and_points


@pytest.mark.parametrize(
    "suite_type,expected_curve",
    [
        (1, NIST256p),
        (2, NIST256p),
        (8, NIST256p),
        (9, NIST256p),
        (3, NIST384p),
        (4, NIST384p),
        (5, NIST521p),
    ],
)
def test_get_curve_and_points_returns_expected_curve_and_bytes(
    suite_type, expected_curve
):
    curve, m, n = get_curve_and_points(suite_type)
    assert curve == expected_curve
    assert isinstance(m, bytes) and len(m) > 0
    assert isinstance(n, bytes) and len(n) > 0
    stored_curve, stored_m, stored_n = spake.DEFAULT_CURVES[suite_type]
    assert (curve, m, n) == (stored_curve, stored_m, stored_n)


def test_all_expected_keys_present_in_default_curves():
    expected_keys = {1, 2, 3, 4, 5, 8, 9}
    assert set(spake.DEFAULT_CURVES.keys()) >= expected_keys


def test_get_curve_and_points_raises_keyerror_for_unsupported_suite():
    with pytest.raises(KeyError) as excinfo:
        get_curve_and_points(0)
    assert excinfo.value.args[0] == "Unsupported SPAKE2+ suite type: 0"
