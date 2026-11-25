
from __future__ import annotations

import ipaddress
import networkx as nx


def _valid_observed_ip(value: str) -> bool:
    """Return True for valid, non-unspecified IP addresses."""
    try:
        address = ipaddress.ip_address(str(value).strip())
        return not address.is_unspecified
    except (ValueError, TypeError):
        return False


def build_device_graph(devices: list[dict]) -> nx.Graph:
    graph = nx.Graph()

    # -------------------------------------------------
    # 1. Add device and observed IP nodes
    # -------------------------------------------------

    for device in devices:
        mac = str(device.get("mac", "")).strip().lower()

        if not mac:
            continue

        raw_ips = device.get("ips") or (
            [device.get("ip")] if device.get("ip") else []
        )

        valid_ips = sorted({
            str(ip).strip()
            for ip in raw_ips
            if _valid_observed_ip(ip)
        })

        observed_ip = device.get("ip", "")

        display_ip = (
            str(observed_ip).strip()
            if _valid_observed_ip(observed_ip)
            else (valid_ips[-1] if valid_ips else "")
        )

        try:
            risk_score = int(device.get("risk_score", 0))
        except (TypeError, ValueError):
            risk_score = 0

        graph.add_node(
            mac,
            kind="device",
            ip=display_ip,
            hostname=device.get("hostname", ""),
            status=device.get("status", ""),
            risk_score=risk_score,
        )

        for ip in valid_ips:
            graph.add_node(
                ip,
                kind="ip",
            )

            graph.add_edge(
                mac,
                ip,
                relation="observed-address",
            )

    # -------------------------------------------------
    # 2. Connect devices to their observed IPv4 subnets
    # -------------------------------------------------

    for device in devices:
        mac = str(device.get("mac", "")).strip().lower()

        if not mac or not graph.has_node(mac):
            continue

        raw_ips = device.get("ips") or (
            [device.get("ip")] if device.get("ip") else []
        )

        for ip in raw_ips:
            if not _valid_observed_ip(ip):
                continue

            try:
                address = ipaddress.ip_address(str(ip).strip())

                # IPv4 /24 subnet grouping only.
                if not isinstance(address, ipaddress.IPv4Address):
                    continue

                subnet = str(
                    ipaddress.ip_network(
                        f"{address}/24",
                        strict=False,
                    )
                )

            except ValueError:
                continue

            subnet_node = f"subnet:{subnet}"

            graph.add_node(
                subnet_node,
                kind="subnet",
                label=subnet,
            )

            graph.add_edge(
                mac,
                subnet_node,
                relation="observed-subnet",
            )

    return graph


def graph_to_dict(graph: nx.Graph) -> dict:
    return {
        "nodes": [
            {
                "id": str(node),
                **attributes,
            }
            for node, attributes in graph.nodes(data=True)
        ],
        "edges": [
            {
                "source": str(source),
                "target": str(target),
                **attributes,
            }
            for source, target, attributes in graph.edges(data=True)
        ],
    }
