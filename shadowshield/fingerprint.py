
from __future__ import annotations

import hashlib
import json


FINGERPRINT_FIELDS = ("vendor", "hostname", "ports", "protocols")


def _normalize_text(value) -> str:
    """Convert values to normalized text without turning None into 'none'."""
    if value is None:
        return ""

    return str(value).strip()


def make_fingerprint(device: dict) -> dict:
    vendor = _normalize_text(device.get("vendor")).lower()
    hostname = _normalize_text(device.get("hostname")).lower()

    raw_ports = device.get("ports") or []
    raw_protocols = device.get("protocols") or []

    fields = {
        "vendor": vendor,
        "hostname": hostname,
        "ports": sorted({
            _normalize_text(port)
            for port in raw_ports
            if _normalize_text(port)
        }),
        "protocols": sorted({
            _normalize_text(protocol).upper()
            for protocol in raw_protocols
            if _normalize_text(protocol)
        }),
    }

    raw = json.dumps(
        fields,
        sort_keys=True,
        separators=(",", ":")
    )

    fields["fingerprint_hash"] = hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()[:16]

    return fields


def comparable_mismatches(
    observed: dict,
    approved: dict
) -> list[str]:

    observed_fp = make_fingerprint(observed)
    approved_fp = approved.get("fingerprint") or make_fingerprint(approved)

    mismatches = []

    for field in FINGERPRINT_FIELDS:
        observed_value = observed_fp.get(field)
        approved_value = approved_fp.get(field)

        # Missing information is not evidence of a mismatch.
        if not observed_value or not approved_value:
            continue

        if observed_value != approved_value:
            mismatches.append(field)

    return mismatches


def identity_field_count(device: dict) -> int:
    return sum(
        bool(_normalize_text(device.get(key)))
        for key in ("mac", "ip", "hostname", "vendor")
    )
