
from __future__ import annotations

import time

from scapy.all import ARP, Ether

import shadowshield.live_collector as collector_module
from shadowshield.live_collector import LiveNetworkCollector


def make_arp_packet(
    mac: str,
    source_ip: str,
    destination_ip: str = "192.168.1.1",
):
    return (
        Ether()
        / ARP(
            op=1,
            hwsrc=mac,
            psrc=source_ip,
            hwdst="ff:ff:ff:ff:ff:ff",
            pdst=destination_ip,
        )
    )


def make_collector(results: list[dict]) -> LiveNetworkCollector:
    return LiveNetworkCollector(
        interface="test-interface",
        observation_callback=results.append,
        subnet="192.168.1.0/24",
    )


def test_collector_accepts_device_inside_subnet():
    results = []
    collector = make_collector(results)

    packet = make_arp_packet(
        mac="02:00:00:00:00:01",
        source_ip="192.168.1.10",
    )

    collector._process_packet(packet)

    assert len(results) == 1
    assert results[0]["mac"] == "02:00:00:00:00:01"
    assert results[0]["ip"] == "192.168.1.10"
    assert len(collector.get_devices()) == 1


def test_collector_ignores_device_outside_subnet():
    results = []
    collector = make_collector(results)

    packet = make_arp_packet(
        mac="02:00:00:00:00:02",
        source_ip="192.168.2.10",
        destination_ip="192.168.2.1",
    )

    collector._process_packet(packet)

    assert results == []
    assert len(collector.get_devices()) == 0


def test_collector_rejects_multicast_source_mac():
    results = []
    collector = make_collector(results)

    packet = make_arp_packet(
        mac="01:00:5e:00:00:01",
        source_ip="192.168.1.20",
    )

    collector._process_packet(packet)

    assert results == []
    assert len(collector.get_devices()) == 0


def test_collector_rejects_unspecified_source_ip():
    results = []
    collector = make_collector(results)

    packet = make_arp_packet(
        mac="02:00:00:00:00:04",
        source_ip="0.0.0.0",
    )

    collector._process_packet(packet)

    assert results == []
    assert len(collector.get_devices()) == 0


def test_collector_stop_joins_capture_thread(monkeypatch):
    results = []
    collector = make_collector(results)

    def fake_sniff(**kwargs):
        time.sleep(0.02)

    monkeypatch.setattr(
        collector_module,
        "sniff",
        fake_sniff,
    )

    collector.start()

    capture_thread = collector._thread

    assert capture_thread is not None
    assert capture_thread.is_alive()

    collector.stop(timeout=2.0)

    assert not capture_thread.is_alive()
