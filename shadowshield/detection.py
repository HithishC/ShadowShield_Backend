from __future__ import annotations

from .fingerprint import comparable_mismatches
from .risk import calculate_risk


def _has_usable_identity(observed: dict) -> bool:
    """
    Check whether the observation has useful identity evidence.
    A MAC address alone is not sufficient for this check.
    """

    ip = str(observed.get("ip", "")).strip().lower()

    invalid_ips = {
        "",
        "0.0.0.0",
        "unknown",
        "none",
        "n/a",
        "-",
    }

    has_ip = ip not in invalid_ips

    has_hostname = bool(
        str(observed.get("hostname", "")).strip()
    )

    has_vendor = bool(
        str(observed.get("vendor", "")).strip()
    )

    return has_ip or has_hostname or has_vendor


def _authorization_status(status: str) -> tuple[str, str]:
    """
    Authorization is separate from security risk.
    """

    mapping = {
        "Known": (
            "Authorized",
            "Device matches approved inventory.",
        ),
        "Unknown": (
            "Unauthorized",
            "Device is not in approved inventory.",
        ),
        "Changed": (
            "Review Required",
            "Observed device details differ from approved inventory.",
        ),
        "Insufficient Evidence": (
            "Review Required",
            "Not enough identifying information to determine authorization.",
        ),
    }

    return mapping.get(
        status,
        (
            "Review Required",
            "Authorization could not be determined.",
        ),
    )


def compare_device(
    observed: dict,
    approved_by_mac: dict,
    policy: dict | None = None,
) -> dict:

    mac = str(
        observed.get("mac", "")
    ).strip().lower()

    approved = approved_by_mac.get(mac)

    mismatches = []

    if not _has_usable_identity(observed):
        status = "Insufficient Evidence"

    elif approved is None:
        status = "Unknown"

    else:
        mismatches = comparable_mismatches(
            observed,
            approved,
        )

        status = (
            "Changed"
            if mismatches
            else "Known"
        )

    authorization, authorization_reason = (
        _authorization_status(status)
    )

    risk = calculate_risk(
        status,
        observed,
        approved,
        policy,
    )

    return {
        **observed,

        "status": status,

        "authorization_status": authorization,
        "authorization_reason": authorization_reason,

        "risk_score": risk["score"],
        "risk_band": risk["band"],
        "risk_reasons": risk["reasons"],

        "mismatch_fields": mismatches,

        "observed_ports": risk["observed_ports"],
        "unexpected_ports": risk["unexpected_ports"],
        "port_analysis": risk["port_analysis"],
    }


def analyze_devices(
    observed_devices: list[dict],
    approved_by_mac: dict,
    policy: dict | None = None,
) -> list[dict]:

    return [
        compare_device(
            device,
            approved_by_mac,
            policy,
        )
        for device in observed_devices
    ]