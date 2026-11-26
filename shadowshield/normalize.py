from __future__ import annotations

from datetime import datetime, timezone
import pandas as pd

EXPECTED_COLUMNS = [
    "mac",
    "ip",
    "hostname",
    "vendor",
    "ports",
    "protocols",
    "seen_at",
    "connection_type",
    "connection_evidence",
]

ALIASES = {
    "mac address": "mac",
    "mac_address": "mac",
    "macaddress": "mac",
    "physical address": "mac",
    "hardware address": "mac",
    "source mac": "mac",
    "ip address": "ip",
    "ip_address": "ip",
    "ipv4": "ip",
    "device name": "hostname",
    "host name": "hostname",
    "host": "hostname",
    "manufacturer": "vendor",
    "device vendor": "vendor",
    "open ports": "ports",
    "port": "ports",
    "service protocols": "protocols",
    "protocol": "protocols",
    "last seen": "seen_at",
    "timestamp": "seen_at",
    "time": "seen_at",
    "connection type": "connection_type",
    "link type": "connection_type",
    "connection evidence": "connection_evidence",
}

def normalize_mac(value) -> str:
    if pd.isna(value) or not str(value).strip():
        return ""

    mac = str(value).strip().lower().replace("-", ":")

    if "." in mac and ":" not in mac:
        compact = mac.replace(".", "")
        if len(compact) == 12:
            mac = ":".join(
                compact[i:i + 2]
                for i in range(0, 12, 2)
            )

    return mac


def parse_list(value) -> list[str]:
    if pd.isna(value) or not str(value).strip():
        return []

    value = str(value).replace(";", ",")

    return sorted({
        item.strip()
        for item in value.split(",")
        if item.strip()
    })


def normalize_observations(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    names = []

    for col in df.columns:
        name = " ".join(
            str(col).replace("\ufeff", "").strip().lower().split()
        )
        names.append(ALIASES.get(name, name))

    df.columns = names

    if "mac" not in df.columns:
        raise ValueError(
            "Missing MAC address column. Use 'mac' or 'MAC Address'."
        )

    if df.columns.duplicated().any():
        merged = {}

        for col in dict.fromkeys(df.columns):
            block = df.loc[:, df.columns == col]
            merged[col] = block.bfill(axis=1).iloc[:, 0]

        df = pd.DataFrame(merged)

    for col in EXPECTED_COLUMNS:
        if col not in df.columns:
            df[col] = ""

    df["mac"] = df["mac"].apply(normalize_mac)

    for col in (
        "ip",
        "hostname",
        "vendor",
        "protocols",
        "seen_at",
        "connection_type",
        "connection_evidence",
    ):
        df[col] = (
            df[col]
            .fillna("")
            .astype(str)
            .str.strip()
        )

    df["connection_type"] = (
        df["connection_type"]
        .str.lower()
        .replace({
            "wifi": "Wi-Fi",
            "wi-fi": "Wi-Fi",
            "wireless": "Wi-Fi",
            "ethernet": "Ethernet",
            "mixed": "Mixed",
        })
    )

    df.loc[
        ~df["connection_type"].isin(
            ["Wi-Fi", "Ethernet", "Mixed"]
        ),
        "connection_type",
    ] = "Unknown"

    df["ports"] = df["ports"].apply(parse_list)

    df["protocols"] = df["protocols"].apply(
        lambda x: [p.upper() for p in parse_list(x)]
    )

    now = datetime.now(timezone.utc).isoformat()

    df.loc[
        df["seen_at"] == "",
        "seen_at"
    ] = now

    df = df[df["mac"] != ""].copy()

    if df.empty:
        raise ValueError(
            "No valid MAC addresses found in the file."
        )

    return df[EXPECTED_COLUMNS].reset_index(drop=True)