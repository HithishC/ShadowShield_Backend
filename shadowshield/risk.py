
from __future__ import annotations

from config import (
    DEFAULT_ALLOWED_PORTS,
    RISK_UNKNOWN,
    RISK_UNEXPECTED_PORT,
    RISK_CHANGED,
    RISK_INSUFFICIENT,
    MIN_IDENTITY_FIELDS,
)

from .fingerprint import identity_field_count


def _normalize_ports(values) -> set[int]:
    """Convert valid port values into integers."""
    ports = set()

    for port in values or []:
        try:
            value = int(port)
            if 1 <= value <= 65535:
                ports.add(value)
        except (TypeError, ValueError):
            continue

    return ports


def calculate_risk(
    status: str,
    observed: dict,
    approved: dict | None,
    policy: dict | None = None
) -> dict:

    policy = policy or {}
    score = 0
    reasons = []

    # Rule 1: Unknown device detection
    if status == "Unknown":
        points = int(policy.get("unknown", RISK_UNKNOWN))
        score += points
        reasons.append(
            f"Device is not in approved inventory (+{points})"
        )

    source = str(observed.get("source", "")).lower()

    # Normalize observed traffic ports
    traffic_ports = _normalize_ports(
        observed.get("ports", [])
    )

    # Normalize explicitly identified listening ports
    listening_ports = _normalize_ports(
        observed.get("listening_ports", [])
    )

    # Live packet capture records traffic ports, not confirmed
    # listening services. Do not treat them as open ports.
    if source == "live_network":
        observed_ports = listening_ports
        port_evidence = "listening"
    else:
        # Preserve existing CSV/PCAP behavior.
        observed_ports = traffic_ports
        port_evidence = "observed"

    # Normalize observed protocols
    observed_protocols = {
        str(protocol).strip().upper()
        for protocol in (observed.get("protocols") or [])
    }

    # Identify standard DHCP ports
    dhcp_ports = []

    if "DHCP" in observed_protocols:
        dhcp_ports = sorted(
            observed_ports.intersection({67, 68})
        )

    # Exclude standard DHCP ports from unexpected-port scoring
    ports_for_check = (
        observed_ports - {67, 68}
        if "DHCP" in observed_protocols
        else observed_ports
    )

    # Approved device port baseline
    approved_ports = _normalize_ports(
        approved.get(
            "allowed_ports",
            approved.get("ports", [])
        ) if approved else []
    )

    # Global allowed port baseline
    global_ports = _normalize_ports(
        policy.get("allowed_ports", DEFAULT_ALLOWED_PORTS)
    )

    port_baseline = (
        approved_ports if approved_ports else global_ports
    )

    unexpected = sorted(
        ports_for_check - port_baseline
    )

    # Rule 2: Unexpected port detection
    if unexpected:
        points = int(
            policy.get(
                "unexpected_port",
                RISK_UNEXPECTED_PORT
            )
        )

        score += points

        reasons.append(
            f"Observed port(s) outside baseline: "
            f"{unexpected} (+{points})"
        )

    # Port analysis explanation
    if source == "live_network":
        if listening_ports:
            if unexpected:
                port_analysis = (
                    "Explicitly identified listening ports "
                    f"outside baseline: {unexpected}."
                )
            else:
                port_analysis = (
                    "Explicitly identified listening ports "
                    "are within the configured baseline."
                )
        else:
            port_analysis = (
                "Traffic ports were observed, but listening "
                "services have not been established. "
                "No unexpected-service risk was assigned."
            )

    elif dhcp_ports:
        port_analysis = (
            "Standard DHCP ports detected; "
            "no DHCP port anomaly identified."
        )

    elif unexpected:
        port_analysis = (
            f"Unexpected port activity detected: {unexpected}."
        )

    elif observed_ports:
        port_analysis = (
            "Observed ports are within the configured baseline."
        )

    else:
        port_analysis = "No port information available."

    # Rule 3: Changed device fingerprint
    if status == "Changed":
        points = int(policy.get("changed", RISK_CHANGED))
        score += points

        reasons.append(
            f"Observed profile differs from approved baseline "
            f"(+{points})"
        )

    # Rule 4: Insufficient identity evidence
    if identity_field_count(observed) < MIN_IDENTITY_FIELDS:
        points = int(
            policy.get("insufficient", RISK_INSUFFICIENT)
        )

        score += points

        reasons.append(
            f"Insufficient identity fields for reliable profiling "
            f"(+{points})"
        )

    # Final risk score
    score = max(0, min(100, score))

    if score < 30:
        band = "Low"
    elif score < 60:
        band = "Medium"
    else:
        band = "High"

    if not reasons:
        reasons.append(
            "No configured risk rules were triggered"
        )

    return {
        "score": score,
        "band": band,
        "reasons": reasons,
        "observed_ports": sorted(observed_ports),
        "traffic_ports": sorted(traffic_ports),
        "listening_ports": sorted(listening_ports),
        "unexpected_ports": unexpected,
        "port_analysis": port_analysis,
    }
