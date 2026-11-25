
from __future__ import annotations

from .fingerprint import comparable_mismatches
from .risk import calculate_risk


def compare_device(
    observed: dict,
    approved_by_mac: dict,
    policy: dict | None = None
) -> dict:

    mac = str(observed.get("mac", "")).strip().lower()
    approved = approved_by_mac.get(mac)
    mismatches = []

    if (
        not observed.get("ip")
        and not observed.get("hostname")
        and not observed.get("vendor")
    ):
        status = "Insufficient Evidence"

    elif approved is None:
        status = "Unknown"

    else:
        mismatches = comparable_mismatches(observed, approved)
        status = "Changed" if mismatches else "Known"

    risk = calculate_risk(
        status,
        observed,
        approved,
        policy
    )

    return {
        **observed,

        "status": status,

        "risk_score": risk["score"],
        "risk_band": risk["band"],
        "risk_reasons": risk["reasons"],

        "mismatch_fields": mismatches,

        # Port analysis information
        "observed_ports": risk["observed_ports"],
        "unexpected_ports": risk["unexpected_ports"],
        "port_analysis": risk["port_analysis"],
    }


def analyze_devices(
    observed_devices: list[dict],
    approved_by_mac: dict,
    policy: dict | None = None
) -> list[dict]:

    return [
        compare_device(device, approved_by_mac, policy)
        for device in observed_devices
    ]
    