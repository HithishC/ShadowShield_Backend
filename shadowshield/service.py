from __future__ import annotations

from .discovery import load_csv, parse_pcap, aggregate_devices
from .detection import analyze_devices
from .storage import get_approved_inventory, save_analysis
from .graph import build_device_graph, graph_to_dict


def analyze_file(
    file_obj,
    filename: str,
    source_type: str,
    policy: dict | None = None,
) -> dict:

    source_type = source_type.lower()

    if source_type == "csv":
        normalized = load_csv(file_obj)

    elif source_type in ("pcap", "pcapng"):
        normalized = parse_pcap(file_obj)

    else:
        raise ValueError(
            "Unsupported file type. Upload CSV, PCAP, or PCAPNG."
        )

    devices = aggregate_devices(normalized)

    baseline = get_approved_inventory()

    results = analyze_devices(
        devices,
        baseline,
        policy,
    )

    analysis_id = save_analysis(
        filename,
        source_type,
        devices,
        results,
    )

    graph = build_device_graph(results)

    counts = {
        "total": len(results),

        "known": sum(
            x["status"] == "Known"
            for x in results
        ),

        "unknown": sum(
            x["status"] == "Unknown"
            for x in results
        ),

        "changed": sum(
            x["status"] == "Changed"
            for x in results
        ),

        "insufficient_evidence": sum(
            x["status"] == "Insufficient Evidence"
            for x in results
        ),

        "authorized": sum(
            x.get("authorization_status") == "Authorized"
            for x in results
        ),

        "unauthorized": sum(
            x.get("authorization_status") == "Unauthorized"
            for x in results
        ),

        "review_required": sum(
            x.get("authorization_status") == "Review Required"
            for x in results
        ),

        "wifi": sum(
            x.get("connection_type") == "Wi-Fi"
            for x in results
        ),

        "ethernet": sum(
            x.get("connection_type") == "Ethernet"
            for x in results
        ),

        "unknown_connection": sum(
            x.get("connection_type") == "Unknown"
            for x in results
        ),

        "mixed_connection": sum(
            x.get("connection_type") == "Mixed"
            for x in results
        ),

        "high_risk": sum(
            x["risk_score"] >= 60
            for x in results
        ),
    }

    return {
        "analysis_id": analysis_id,
        "source_name": filename,
        "observation_rows": int(len(normalized)),
        "counts": counts,
        "results": results,
        "graph": graph_to_dict(graph),
    }