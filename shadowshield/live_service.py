
from __future__ import annotations

import ipaddress
import threading
import uuid

from datetime import datetime, timezone
from typing import Optional

from scapy.all import get_if_list

from shadowshield.live_collector import LiveNetworkCollector
from shadowshield.storage import (
    create_live_session,
    update_live_session,
    save_live_observation,
    get_live_session,
)


class LiveDiscoveryService:
    def __init__(self):
        self.sessions = {}
        self._lock = threading.Lock()

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _validate_interface(interface: str):
        interface = str(interface).strip()

        if not interface:
            raise ValueError(
                "Network interface cannot be empty."
            )

        try:
            available_interfaces = get_if_list()
        except Exception as exc:
            raise RuntimeError(
                f"Could not retrieve network interfaces: {exc}"
            ) from exc

        if interface not in available_interfaces:
            raise ValueError(
                f"Invalid network interface: {interface}. "
                "Choose an interface returned by Scapy."
            )

        return interface

    def create_session(
        self,
        interface: str,
        subnet: Optional[str] = None,
    ) -> dict:
        interface = self._validate_interface(interface)

        if subnet is not None:
            subnet = str(subnet).strip()

            try:
                subnet = str(
                    ipaddress.ip_network(
                        subnet,
                        strict=False,
                    )
                )
            except ValueError as exc:
                raise ValueError(
                    "Invalid subnet. Provide a valid IPv4 "
                    "or IPv6 CIDR network."
                ) from exc

        session_id = str(uuid.uuid4())

        session = {
            "session_id": session_id,
            "interface": interface,
            "subnet": subnet,
            "status": "created",
            "started_at": None,
            "stopped_at": None,
            "devices": {},
            "observations_count": 0,
            "errors": [],
            "collector": None,
        }

        create_live_session(
            session_id=session_id,
            interface=interface,
            subnet=subnet,
        )

        with self._lock:
            self.sessions[session_id] = session

        return self._public_session(session)

    def start_session(self, session_id: str) -> dict:
        session = self._get_session(session_id)

        with self._lock:
            if session["status"] == "running":
                collector = session.get("collector")

                if (
                    collector
                    and collector._thread
                    and collector._thread.is_alive()
                    and not collector._stop_event.is_set()
                ):
                    return self._public_session(session)

                raise RuntimeError(
                    "Session is marked running, but its "
                    "capture thread is not healthy. Stop it "
                    "before attempting another start."
                )

            existing_collector = session.get("collector")

            if (
                existing_collector
                and existing_collector._thread
                and existing_collector._thread.is_alive()
            ):
                raise RuntimeError(
                    "The previous collector is still running."
                )

            previous_error_count = len(session["errors"])

        interface = self._validate_interface(
            session["interface"]
        )

        collector = LiveNetworkCollector(
            interface=interface,
            subnet=session["subnet"],
            observation_callback=lambda observation: (
                self._handle_observation(
                    session_id,
                    observation,
                )
            ),
        )

        # Do not update the session to running until the
        # collector confirms that Scapy initialized capture.
        with self._lock:
            session["collector"] = collector

        try:
            collector.start()

            with self._lock:
                new_errors = (
                    len(session["errors"]) > previous_error_count
                )

                if new_errors:
                    raise RuntimeError(
                        "Collector reported an error during startup."
                    )

                started_at = self._now()

                session["started_at"] = started_at
                session["stopped_at"] = None
                session["status"] = "running"

            update_live_session(
                session_id,
                status="running",
                started_at=started_at,
                stopped_at=None,
            )

            return self._public_session(session)

        except Exception as exc:
            try:
                collector.stop(timeout=10.0)
            except Exception:
                pass

            with self._lock:
                session["collector"] = None
                session["status"] = "error"

            update_live_session(
                session_id,
                status="error",
            )

            if isinstance(exc, RuntimeError):
                raise

            raise RuntimeError(
                f"Could not start packet capture: {exc}"
            ) from exc

    def stop_session(self, session_id: str) -> dict:
        session = self._get_session(session_id)
        collector = session.get("collector")

        # Only report stopped after the capture thread exits.
        if collector:
            collector.stop(timeout=10.0)

        stopped_at = self._now()

        with self._lock:
            session["collector"] = None
            session["status"] = "stopped"
            session["stopped_at"] = stopped_at

        update_live_session(
            session_id,
            status="stopped",
            stopped_at=stopped_at,
        )

        return self._public_session(session)

    def get_session(self, session_id: str) -> dict:
        session = self._get_session(session_id)

        with self._lock:
            public_data = self._public_session(session)
            errors = list(session["errors"])
            observations_count = session[
                "observations_count"
            ]

        stored_session = get_live_session(session_id)

        if stored_session:
            devices = stored_session.get("devices", [])
            device_count = stored_session.get(
                "device_count",
                len(devices),
            )
        else:
            devices = []
            device_count = 0

        return {
            **public_data,
            "device_count": device_count,
            "observations_count": observations_count,
            "devices": devices,
            "errors": errors,
        }

    def get_devices(self, session_id: str) -> list[dict]:
        session = self._get_session(session_id)

        stored_session = get_live_session(session_id)

        if stored_session:
            return stored_session.get("devices", [])

        with self._lock:
            return list(session["devices"].values())

    def _handle_observation(
        self,
        session_id: str,
        observation: dict,
    ):
        session = self._get_session(session_id)

        if observation.get("type") == "collector_error":
            with self._lock:
                session["errors"].append(observation)
                session["status"] = "error"

            update_live_session(
                session_id,
                status="error",
            )
            return

        mac = observation.get("mac")

        if not mac:
            return

        save_live_observation(
            session_id,
            observation,
        )

        with self._lock:
            existing = session["devices"].get(mac)

            if existing:
                for field in [
                    "ip",
                    "hostname",
                    "protocols",
                    "ports",
                    "dns_names",
                    "last_seen",
                ]:
                    if observation.get(field):
                        existing[field] = observation[field]
            else:
                session["devices"][mac] = observation.copy()

            session["observations_count"] += 1

    def _get_session(self, session_id: str) -> dict:
        with self._lock:
            session = self.sessions.get(session_id)

        if not session:
            raise KeyError(
                f"Live session not found: {session_id}"
            )

        return session

    @staticmethod
    def _public_session(session: dict) -> dict:
        return {
            "session_id": session["session_id"],
            "interface": session["interface"],
            "subnet": session["subnet"],
            "status": session["status"],
            "started_at": session["started_at"],
            "stopped_at": session["stopped_at"],
        }
