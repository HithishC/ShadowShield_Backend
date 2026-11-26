from __future__ import annotations

from datetime import datetime, timezone
import io
import pandas as pd

from scapy.all import (
    PcapReader,
    Ether,
    ARP,
    IP,
    UDP,
    TCP,
    DNS,
    DHCP,
    Dot11,
    RadioTap,
)

from .normalize import normalize_observations


def load_csv(file_obj) -> pd.DataFrame:
    """
    Safely load CSV observations.

    Supports comma, semicolon and tab delimiters,
    UTF-8, UTF-8 BOM and Latin-1.
    """

    try:
        file_obj.seek(0)
    except (AttributeError, OSError):
        pass

    content = file_obj.read()

    if isinstance(content, bytes):
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = content.decode("latin-1")
    else:
        text = str(content).lstrip("\ufeff")

    if not text.strip():
        raise ValueError("The uploaded CSV file is empty.")

    header = next(
        (line for line in text.splitlines() if line.strip()),
        ""
    )

    delimiter_counts = {
        ",": header.count(","),
        ";": header.count(";"),
        "\t": header.count("\t"),
    }

    delimiter = max(
        delimiter_counts,
        key=delimiter_counts.get
    )

    if delimiter_counts[delimiter] == 0:
        raise ValueError(
            "Could not identify CSV delimiter. "
            "Use comma-separated columns."
        )

    df = pd.read_csv(
        io.StringIO(text),
        dtype=str,
        keep_default_na=False,
        sep=delimiter,
        engine="python",
        on_bad_lines="error",
    )

    if df.empty and len(df.columns) == 0:
        raise ValueError(
            "CSV file does not contain valid columns."
        )

    return normalize_observations(df)


def _dhcp_hostname(packet) -> str:
    try:
        if DHCP in packet:
            for option in packet[DHCP].options:
                if (
                    isinstance(option, tuple)
                    and option[0] == "hostname"
                ):
                    value = option[1]

                    return (
                        value.decode(errors="ignore")
                        if isinstance(value, bytes)
                        else str(value)
                    )
    except Exception:
        pass

    return ""


def _wifi_source_mac(packet) -> str:
    """
    Extract the source/transmitting station MAC from
    an 802.11 frame where possible.
    """

    try:
        if Dot11 not in packet:
            return ""

        dot11 = packet[Dot11]

        to_ds = int(dot11.FCfield & 0x1)
        from_ds = int(dot11.FCfield & 0x2)

        if to_ds and from_ds:
            return dot11.addr4 or dot11.addr2 or ""

        if to_ds:
            return dot11.addr2 or ""

        if from_ds:
            return dot11.addr3 or ""

        return dot11.addr2 or ""

    except (AttributeError, TypeError, ValueError):
        return ""


def _connection_metadata(packet) -> tuple[str, str, str]:
    """
    Returns:
        MAC address,
        connection type,
        evidence

    Ethernet means Ethernet frame metadata, not guaranteed
    physical cable connectivity.
    """

    if Dot11 in packet:
        mac = _wifi_source_mac(packet)

        if RadioTap in packet:
            evidence = "Radiotap + 802.11"
        else:
            evidence = "802.11"

        return mac, "Wi-Fi", evidence

    if Ether in packet:
        mac = packet[Ether].src or ""

        return (
            mac,
            "Ethernet",
            "Ethernet frame metadata",
        )

    return "", "Unknown", "No supported link-layer evidence"


def _packet_ip(packet) -> str:
    if IP in packet:
        return packet[IP].src or ""

    return ""


def parse_pcap(file_obj) -> pd.DataFrame:
    try:
        file_obj.seek(0)
    except (AttributeError, OSError):
        pass

    rows = []

    with PcapReader(file_obj) as reader:
        for packet in reader:
            mac, connection_type, evidence = (
                _connection_metadata(packet)
            )

            ip = _packet_ip(packet)
            hostname = _dhcp_hostname(packet)

            protocols = set()
            ports = set()

            packet_time = datetime.fromtimestamp(
                float(packet.time),
                tz=timezone.utc,
            ).isoformat()

            if connection_type == "Ethernet":
                protocols.add("ETHERNET")

            elif connection_type == "Wi-Fi":
                protocols.add("WIFI")

            if ARP in packet:
                mac = (
                    packet[ARP].hwsrc
                    or mac
                )

                ip = (
                    packet[ARP].psrc
                    or ip
                )

                protocols.add("ARP")

            if IP in packet:
                protocols.add("IP")

            if UDP in packet:
                sport = int(packet[UDP].sport)
                dport = int(packet[UDP].dport)

                if sport:
                    ports.add(sport)

                if dport:
                    ports.add(dport)

                if sport in (67, 68) or dport in (67, 68):
                    protocols.add("DHCP")

                if DNS in packet:
                    protocols.add("DNS")

            if TCP in packet:
                protocols.add("TCP")

                sport = int(packet[TCP].sport)
                dport = int(packet[TCP].dport)

                if sport:
                    ports.add(sport)

                if dport:
                    ports.add(dport)

            if mac:
                rows.append({
                    "mac": mac,
                    "ip": ip,
                    "hostname": hostname,
                    "vendor": "",
                    "ports": ",".join(
                        map(str, sorted(ports))
                    ),
                    "protocols": ",".join(
                        sorted(protocols)
                    ),
                    "seen_at": packet_time,
                    "connection_type": connection_type,
                    "connection_evidence": evidence,
                })

    if not rows:
        raise ValueError(
            "No supported source MAC observations found "
            "in the PCAP/PCAPNG file."
        )

    return normalize_observations(
        pd.DataFrame(rows)
    )


def aggregate_devices(
    observations: pd.DataFrame
) -> list[dict]:

    if observations.empty:
        return []

    devices = []

    for mac, group in observations.groupby(
        "mac",
        sort=True,
    ):
        ordered = group.copy()

        ordered["_parsed_time"] = pd.to_datetime(
            ordered["seen_at"],
            errors="coerce",
            utc=True,
        )

        ordered = ordered.sort_values(
            "_parsed_time",
            na_position="last",
        )

        first_seen = str(
            ordered.iloc[0]["seen_at"]
        )

        last = ordered.iloc[-1]

        ips = sorted({
            str(x).strip()
            for x in group["ip"]
            if str(x).strip()
        })

        hostnames = sorted({
            str(x).strip()
            for x in group["hostname"]
            if str(x).strip()
        })

        vendors = sorted({
            str(x).strip()
            for x in group["vendor"]
            if str(x).strip()
        })

        ports = sorted(
            {
                str(p)
                for row in group["ports"]
                for p in row
            },
            key=lambda x: (
                0, int(x)
            ) if x.isdigit() else (
                1, x
            ),
        )

        protocols = sorted({
            str(p).upper()
            for row in group["protocols"]
            for p in row
        })

        connection_types = sorted({
            str(x).strip()
            for x in group["connection_type"]
            if str(x).strip()
        })

        connection_evidence = sorted({
            str(x).strip()
            for x in group["connection_evidence"]
            if str(x).strip()
        })

        if len(connection_types) == 1:
            connection_type = connection_types[0]
        elif len(connection_types) > 1:
            connection_type = "Mixed"
        else:
            connection_type = "Unknown"

        devices.append({
            "mac": mac,
            "ip": str(last.get("ip", "")),
            "ips": ips,
            "hostname": (
                str(last.get("hostname", ""))
                or (
                    hostnames[-1]
                    if hostnames
                    else ""
                )
            ),
            "hostnames": hostnames,
            "vendor": (
                str(last.get("vendor", ""))
                or (
                    vendors[-1]
                    if vendors
                    else ""
                )
            ),
            "ports": ports,
            "protocols": protocols,
            "first_seen": first_seen,
            "last_seen": str(last.get("seen_at", "")),
            "observations": int(len(group)),
            "connection_type": connection_type,
            "connection_evidence": connection_evidence,
        })

    return devices