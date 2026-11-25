
from __future__ import annotations

from datetime import datetime, timezone
import io
import pandas as pd

from scapy.all import (
    PcapReader, Ether, ARP, IP, UDP, TCP, DNS, DHCP
)

from .normalize import normalize_observations


def load_csv(file_obj) -> pd.DataFrame:
    """
    Safely load CSV observations.

    Supports:
    - Comma-separated CSV
    - Semicolon-separated CSV
    - Tab-separated CSV
    - UTF-8 and UTF-8 BOM
    - Latin-1 encoded files

    Quoted values such as "80,443" remain intact.
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

    # Identify delimiter using the header row.
    header = next(
        (line for line in text.splitlines() if line.strip()),
        ""
    )

    delimiter_counts = {
        ",": header.count(","),
        ";": header.count(";"),
        "\t": header.count("\t"),
    }

    delimiter = max(delimiter_counts, key=delimiter_counts.get)

    if delimiter_counts[delimiter] == 0:
        raise ValueError(
            "Could not identify CSV delimiter. "
            "Use comma-separated columns."
        )

    # Read using the selected delimiter.
    df = pd.read_csv(
        io.StringIO(text),
        dtype=str,
        keep_default_na=False,
        sep=delimiter,
        engine="python",
        on_bad_lines="error"
    )

    if df.empty and len(df.columns) == 0:
        raise ValueError("CSV file does not contain valid columns.")

    return normalize_observations(df)


def _dhcp_hostname(packet) -> str:
    try:
        if DHCP in packet:
            for option in packet[DHCP].options:
                if isinstance(option, tuple) and option[0] == "hostname":
                    value = option[1]
                    return (
                        value.decode(errors="ignore")
                        if isinstance(value, bytes)
                        else str(value)
                    )
    except Exception:
        pass

    return ""


def parse_pcap(file_obj) -> pd.DataFrame:
    try:
        file_obj.seek(0)
    except (AttributeError, OSError):
        pass

    rows = []

    with PcapReader(file_obj) as reader:
        for packet in reader:
            mac, ip = "", ""
            hostname = _dhcp_hostname(packet)

            protocols = set()
            ports = set()

            packet_time = datetime.fromtimestamp(
                float(packet.time),
                tz=timezone.utc
            ).isoformat()

            if Ether in packet:
                mac = packet[Ether].src or ""
                protocols.add("ETHERNET")

            if ARP in packet:
                mac = packet[ARP].hwsrc or mac
                ip = packet[ARP].psrc or ip
                protocols.add("ARP")

            if IP in packet:
                ip = packet[IP].src or ip
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
                    "ports": ",".join(map(str, sorted(ports))),
                    "protocols": ",".join(sorted(protocols)),
                    "seen_at": packet_time
                })

    if not rows:
        raise ValueError(
            "No Ethernet source MAC observations found in the PCAP."
        )

    return normalize_observations(pd.DataFrame(rows))


def aggregate_devices(observations: pd.DataFrame) -> list[dict]:
    if observations.empty:
        return []

    devices = []

    for mac, group in observations.groupby("mac", sort=True):
        ordered = group.copy()

        ordered["_parsed_time"] = pd.to_datetime(
            ordered["seen_at"],
            errors="coerce",
            utc=True
        )

        ordered = ordered.sort_values(
            "_parsed_time",
            na_position="last"
        )

        first_seen = str(ordered.iloc[0]["seen_at"])
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
            key=lambda x: int(x) if x.isdigit() else x
        )

        protocols = sorted({
            str(p).upper()
            for row in group["protocols"]
            for p in row
        })

        devices.append({
            "mac": mac,
            "ip": str(last.get("ip", "")),
            "ips": ips,
            "hostname": (
                str(last.get("hostname", ""))
                or (hostnames[-1] if hostnames else "")
            ),
            "hostnames": hostnames,
            "vendor": (
                str(last.get("vendor", ""))
                or (vendors[-1] if vendors else "")
            ),
            "ports": ports,
            "protocols": protocols,
            "first_seen": first_seen,
            "last_seen": str(last.get("seen_at", "")),
            "observations": int(len(group)),
        })

    return devices
