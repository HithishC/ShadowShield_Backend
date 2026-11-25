
from __future__ import annotations

import ipaddress
import threading
from datetime import datetime, timezone
from typing import Optional

from scapy.all import (
    ARP,
    BOOTP,
    DHCP,
    DNS,
    DNSQR,
    Ether,
    IP,
    IPv6,
    TCP,
    UDP,
    sniff,
)


class LiveNetworkCollector:
    """
    Passive collector for authorized network monitoring.

    Startup is successful only after Scapy completes its first
    capture operation successfully.
    """

    def __init__(
        self,
        interface: str,
        observation_callback,
        subnet: Optional[str] = None,
    ):
        self.interface = str(interface).strip()

        if not self.interface:
            raise ValueError("Network interface cannot be empty.")

        self.subnet = None

        if subnet:
            try:
                self.subnet = ipaddress.ip_network(
                    str(subnet).strip(),
                    strict=False,
                )
            except ValueError as exc:
                raise ValueError("Invalid subnet.") from exc

        self.observation_callback = observation_callback

        self._stop_event = threading.Event()
        self._startup_event = threading.Event()
        self._startup_error = None

        self._thread = None
        self._lock = threading.Lock()

        self._devices = {}
        self._ip_to_mac = {}

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _valid_mac(value: str) -> bool:
        if not value:
            return False

        mac = str(value).strip().lower()
        parts = mac.split(":")

        if len(parts) != 6:
            return False

        try:
            octets = [int(part, 16) for part in parts]
        except ValueError:
            return False

        if any(len(part) != 2 for part in parts):
            return False

        if all(octet == 0 for octet in octets):
            return False

        if all(octet == 255 for octet in octets):
            return False

        if octets[0] & 1:
            return False

        return True

    @staticmethod
    def _valid_ip(value: str) -> bool:
        try:
            address = ipaddress.ip_address(str(value).strip())

            return (
                not address.is_unspecified
                and not address.is_multicast
            )
        except ValueError:
            return False

    def _in_subnet(self, ip: str) -> bool:
        if not self._valid_ip(ip):
            return False

        if self.subnet is None:
            return True

        try:
            address = ipaddress.ip_address(str(ip).strip())

            return (
                address.version == self.subnet.version
                and address in self.subnet
            )
        except ValueError:
            return False

    @staticmethod
    def _decode_name(value) -> str:
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="ignore")

        return str(value).strip().rstrip(".")

    def _emit(self, observation: dict):
        try:
            self.observation_callback(observation)
        except Exception:
            pass

    def _emit_error(self, message: str):
        self._emit(
            {
                "type": "collector_error",
                "message": str(message),
                "timestamp": self._now(),
            }
        )

    def _update_device(
        self,
        mac: str,
        ip: str,
        protocol: str,
        hostname: Optional[str] = None,
        ports=None,
        dns_names=None,
    ):
        mac = str(mac).strip().lower()
        ip = str(ip).strip()

        if not self._valid_mac(mac):
            return

        if not self._in_subnet(ip):
            return

        with self._lock:
            self._ip_to_mac[ip] = mac

            device = self._devices.get(mac)

            if device is None:
                device = {
                    "mac": mac,
                    "ip": ip,
                    "hostname": None,
                    "protocols": [],
                    "ports": [],
                    "dns_names": [],
                    "last_seen": self._now(),
                    "observation_count": 0,
                }

                self._devices[mac] = device

            device["ip"] = ip

            if hostname:
                device["hostname"] = str(hostname).strip()

            protocols = set(device.get("protocols", []))
            protocols.update(str(protocol).split(","))
            device["protocols"] = sorted(protocols)

            observed_ports = set(device.get("ports", []))

            if ports:
                for port in ports:
                    try:
                        port = int(port)

                        if 1 <= port <= 65535:
                            observed_ports.add(port)
                    except (TypeError, ValueError):
                        continue

            device["ports"] = sorted(observed_ports)

            observed_names = set(device.get("dns_names", []))

            if dns_names:
                for name in dns_names:
                    name = self._decode_name(name)

                    if name:
                        observed_names.add(name)

            device["dns_names"] = sorted(observed_names)
            device["last_seen"] = self._now()
            device["observation_count"] += 1

            observation = device.copy()

        self._emit(observation)

    def _process_packet(self, packet):
        if not packet.haslayer(Ether):
            return

        ethernet = packet[Ether]
        source_mac = str(ethernet.src).strip().lower()

        if not self._valid_mac(source_mac):
            return

        protocols = set()
        source_ip = None
        hostname = None
        ports = set()
        dns_names = set()

        if packet.haslayer(ARP):
            arp = packet[ARP]
            protocols.add("ARP")

            source_mac = str(arp.hwsrc).strip().lower()
            source_ip = str(arp.psrc).strip()

            if not self._valid_mac(source_mac):
                return

        if packet.haslayer(IP):
            source_ip = str(packet[IP].src)
            protocols.add("IP")

        elif packet.haslayer(IPv6):
            source_ip = str(packet[IPv6].src)
            protocols.add("IPv6")

        if packet.haslayer(BOOTP):
            protocols.add("DHCP")
            bootp = packet[BOOTP]

            try:
                dhcp_mac = ":".join(
                    f"{byte:02x}" for byte in bootp.chaddr[:6]
                )

                if self._valid_mac(dhcp_mac):
                    source_mac = dhcp_mac
            except Exception:
                pass

            assigned_ip = str(bootp.yiaddr).strip()

            if self._valid_ip(assigned_ip):
                source_ip = assigned_ip

        if packet.haslayer(DHCP):
            protocols.add("DHCP")

            for option in packet[DHCP].options:
                if (
                    isinstance(option, tuple)
                    and option[0] == "hostname"
                ):
                    hostname = self._decode_name(option[1])

        if packet.haslayer(TCP):
            protocols.add("TCP")
            tcp = packet[TCP]
            ports.update([int(tcp.sport), int(tcp.dport)])

        if packet.haslayer(UDP):
            protocols.add("UDP")
            udp = packet[UDP]
            ports.update([int(udp.sport), int(udp.dport)])

        if packet.haslayer(DNS):
            protocols.add("DNS")
            dns = packet[DNS]

            if int(dns.qr) == 0 and packet.haslayer(DNSQR):
                query_name = self._decode_name(
                    packet[DNSQR].qname
                )

                if query_name:
                    dns_names.add(query_name)

        if not source_ip or not self._in_subnet(source_ip):
            return

        if not protocols:
            return

        self._update_device(
            mac=source_mac,
            ip=source_ip,
            protocol=",".join(sorted(protocols)),
            hostname=hostname,
            ports=ports,
            dns_names=dns_names,
        )

    def _capture_loop(self):
        try:
            while not self._stop_event.is_set():
                sniff(
                    iface=self.interface,
                    timeout=1,
                    store=False,
                    prn=self._process_packet,
                )

                # Confirm startup only after Scapy has completed
                # its first capture operation successfully.
                if not self._startup_event.is_set():
                    self._startup_event.set()

        except Exception as exc:
            self._startup_error = exc
            self._startup_event.set()

            if not self._stop_event.is_set():
                self._emit_error(
                    f"Packet capture failed: {exc}"
                )

            self._stop_event.set()

    def start(self, startup_timeout: float = 5.0):
        if self._thread and self._thread.is_alive():
            if self._stop_event.is_set():
                raise RuntimeError(
                    "Previous collector thread is still stopping."
                )

            return

        self._stop_event.clear()
        self._startup_event.clear()
        self._startup_error = None

        self._thread = threading.Thread(
            target=self._capture_loop,
            name="ShadowShieldLiveCollector",
            daemon=True,
        )

        self._thread.start()

        if not self._startup_event.wait(timeout=startup_timeout):
            self._stop_event.set()
            self._thread.join(timeout=10.0)

            raise RuntimeError(
                "Packet capture startup timed out."
            )

        if self._startup_error is not None:
            error = self._startup_error
            self._thread.join(timeout=10.0)

            raise RuntimeError(
                f"Packet capture could not start: {error}"
            ) from error

        if self._stop_event.is_set():
            raise RuntimeError(
                "Packet capture stopped during startup."
            )

    def stop(self, timeout: float = 10.0):
        self._stop_event.set()

        if self._thread:
            self._thread.join(timeout=timeout)

            if self._thread.is_alive():
                raise RuntimeError(
                    "Collector capture thread did not stop "
                    "within the requested timeout."
                )

    def get_devices(self) -> list[dict]:
        with self._lock:
            return [
                device.copy()
                for device in self._devices.values()
            ]
