
from __future__ import annotations

import json
import sqlite3
import uuid

from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager

from config import DB_PATH
from .fingerprint import make_fingerprint
from .normalize import normalize_mac


@contextmanager
def connect(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: str = DB_PATH):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    with connect(db_path) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS approved_inventory (
            mac TEXT PRIMARY KEY,
            ip TEXT,
            hostname TEXT,
            vendor TEXT,
            ports TEXT NOT NULL DEFAULT '[]',
            protocols TEXT NOT NULL DEFAULT '[]',
            fingerprint TEXT NOT NULL DEFAULT '{}',
            allowed_ports TEXT NOT NULL DEFAULT '[]',
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS analyses (
            id TEXT PRIMARY KEY,
            source_name TEXT,
            source_type TEXT,
            device_count INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT NOT NULL,
            mac TEXT,
            ip TEXT,
            hostname TEXT,
            vendor TEXT,
            ports TEXT,
            protocols TEXT,
            first_seen TEXT,
            last_seen TEXT,
            observation_count INTEGER,
            FOREIGN KEY(analysis_id)
                REFERENCES analyses(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS analysis_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT NOT NULL,
            mac TEXT NOT NULL,
            status TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_band TEXT NOT NULL,
            result_json TEXT NOT NULL,
            FOREIGN KEY(analysis_id)
                REFERENCES analyses(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT NOT NULL,
            mac TEXT NOT NULL,
            status TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_band TEXT NOT NULL,
            reasons TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(analysis_id)
                REFERENCES analyses(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_alerts_created
            ON alerts(created_at DESC);

        CREATE INDEX IF NOT EXISTS idx_results_analysis
            ON analysis_results(analysis_id);

        -- NEW: Live discovery sessions
        CREATE TABLE IF NOT EXISTS live_sessions (
            session_id TEXT PRIMARY KEY,
            interface TEXT NOT NULL,
            subnet TEXT,
            status TEXT NOT NULL DEFAULT 'created',
            started_at TEXT,
            stopped_at TEXT,
            created_at TEXT NOT NULL
        );

        -- NEW: Devices observed during live sessions
        CREATE TABLE IF NOT EXISTS live_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            mac TEXT NOT NULL,
            ip TEXT,
            hostname TEXT,
            protocols TEXT NOT NULL DEFAULT '[]',
            ports TEXT NOT NULL DEFAULT '[]',
            dns_names TEXT NOT NULL DEFAULT '[]',
            source TEXT NOT NULL DEFAULT 'live_network',
            first_seen TEXT,
            last_seen TEXT,
            observation_count INTEGER NOT NULL DEFAULT 1,

            UNIQUE(session_id, mac),

            FOREIGN KEY(session_id)
                REFERENCES live_sessions(session_id)
                ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_live_observations_session
            ON live_observations(session_id);

        CREATE INDEX IF NOT EXISTS idx_live_sessions_created
            ON live_sessions(created_at DESC);
        """)


def _dump(value):
    return json.dumps(
        value if value is not None else [],
        ensure_ascii=False,
    )


def _load(value, default=None):
    if value is None:
        return default if default is not None else []

    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default if default is not None else []


def _now():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------
# Existing approved inventory functions
# ---------------------------------------------------------

def upsert_approved(device: dict, db_path: str = DB_PATH):
    mac = normalize_mac(device.get("mac", ""))

    if not mac:
        raise ValueError("MAC address is required.")

    fp = make_fingerprint(device)
    now = _now()

    allowed = (
        device.get("allowed_ports")
        or device.get("ports")
        or []
    )

    with connect(db_path) as conn:
        conn.execute("""
        INSERT INTO approved_inventory
        (
            mac, ip, hostname, vendor, ports, protocols,
            fingerprint, allowed_ports, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)

        ON CONFLICT(mac) DO UPDATE SET
            ip=excluded.ip,
            hostname=excluded.hostname,
            vendor=excluded.vendor,
            ports=excluded.ports,
            protocols=excluded.protocols,
            fingerprint=excluded.fingerprint,
            allowed_ports=excluded.allowed_ports,
            updated_at=excluded.updated_at
        """, (
            mac,
            device.get("ip", ""),
            device.get("hostname", ""),
            device.get("vendor", ""),
            _dump(device.get("ports", [])),
            _dump(device.get("protocols", [])),
            json.dumps(fp),
            _dump(allowed),
            now,
        ))


def delete_approved(mac: str, db_path: str = DB_PATH) -> bool:
    mac = normalize_mac(mac)

    with connect(db_path) as conn:
        cursor = conn.execute(
            "DELETE FROM approved_inventory WHERE mac=?",
            (mac,),
        )

        return cursor.rowcount > 0


def get_approved_inventory(db_path: str = DB_PATH) -> dict:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM approved_inventory ORDER BY mac"
        ).fetchall()

    result = {}

    for row in rows:
        item = dict(row)

        for key in ("ports", "protocols", "allowed_ports"):
            item[key] = _load(item[key])

        item["fingerprint"] = _load(
            item["fingerprint"],
            {},
        )

        result[item["mac"]] = item

    return result


# ---------------------------------------------------------
# Existing analysis functions
# ---------------------------------------------------------

def save_analysis(
    source_name: str,
    source_type: str,
    observations: list[dict],
    results: list[dict],
    db_path: str = DB_PATH,
) -> str:
    analysis_id = str(uuid.uuid4())
    now = _now()

    with connect(db_path) as conn:
        conn.execute("""
        INSERT INTO analyses
        (id, source_name, source_type, device_count, created_at)
        VALUES (?, ?, ?, ?, ?)
        """, (
            analysis_id,
            source_name,
            source_type,
            len(results),
            now,
        ))

        for device in observations:
            conn.execute("""
            INSERT INTO observations
            (
                analysis_id, mac, ip, hostname, vendor,
                ports, protocols, first_seen, last_seen,
                observation_count
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                analysis_id,
                device.get("mac", ""),
                device.get("ip", ""),
                device.get("hostname", ""),
                device.get("vendor", ""),
                _dump(device.get("ports", [])),
                _dump(device.get("protocols", [])),
                device.get("first_seen", ""),
                device.get("last_seen", ""),
                device.get("observations", 1),
            ))

        for result in results:
            conn.execute("""
            INSERT INTO analysis_results
            (
                analysis_id, mac, status, risk_score,
                risk_band, result_json
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """, (
                analysis_id,
                result.get("mac", ""),
                result["status"],
                result["risk_score"],
                result["risk_band"],
                json.dumps(result, ensure_ascii=False),
            ))

            if (
                result["status"] in (
                    "Unknown",
                    "Changed",
                    "Insufficient Evidence",
                )
                or result["risk_score"] >= 30
            ):
                conn.execute("""
                INSERT INTO alerts
                (
                    analysis_id, mac, status, risk_score,
                    risk_band, reasons, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    analysis_id,
                    result.get("mac", ""),
                    result["status"],
                    result["risk_score"],
                    result["risk_band"],
                    _dump(result.get("risk_reasons", [])),
                    now,
                ))

    return analysis_id


def get_analyses(
    limit: int = 50,
    db_path: str = DB_PATH,
) -> list[dict]:
    with connect(db_path) as conn:
        rows = conn.execute("""
        SELECT * FROM analyses
        ORDER BY created_at DESC
        LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


def get_analysis(
    analysis_id: str,
    db_path: str = DB_PATH,
) -> dict | None:
    with connect(db_path) as conn:
        head = conn.execute(
            "SELECT * FROM analyses WHERE id=?",
            (analysis_id,),
        ).fetchone()

        if not head:
            return None

        rows = conn.execute("""
        SELECT result_json
        FROM analysis_results
        WHERE analysis_id=?
        ORDER BY id
        """, (analysis_id,)).fetchall()

    data = dict(head)

    data["results"] = [
        json.loads(row["result_json"])
        for row in rows
    ]

    return data


def get_recent_alerts(
    limit: int = 100,
    db_path: str = DB_PATH,
) -> list[dict]:
    with connect(db_path) as conn:
        rows = conn.execute("""
        SELECT * FROM alerts
        ORDER BY id DESC
        LIMIT ?
        """, (limit,)).fetchall()

    items = []

    for row in rows:
        item = dict(row)
        item["reasons"] = _load(item["reasons"])
        items.append(item)

    return items


# ---------------------------------------------------------
# NEW: Live discovery session storage
# ---------------------------------------------------------

def create_live_session(
    session_id: str,
    interface: str,
    subnet: str | None = None,
    db_path: str = DB_PATH,
) -> dict:
    now = _now()

    with connect(db_path) as conn:
        conn.execute("""
        INSERT INTO live_sessions
        (
            session_id, interface, subnet,
            status, started_at, stopped_at, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id,
            interface,
            subnet,
            "created",
            None,
            None,
            now,
        ))

    return get_live_session(session_id, db_path)


def update_live_session(
    session_id: str,
    status: str | None = None,
    started_at: str | None = None,
    stopped_at: str | None = None,
    db_path: str = DB_PATH,
) -> bool:
    allowed_statuses = {
        "created",
        "running",
        "stopped",
        "error",
    }

    if status is not None and status not in allowed_statuses:
        raise ValueError("Invalid live session status.")

    updates = []
    values = []

    if status is not None:
        updates.append("status=?")
        values.append(status)

    if started_at is not None:
        updates.append("started_at=?")
        values.append(started_at)

    if stopped_at is not None:
        updates.append("stopped_at=?")
        values.append(stopped_at)

    if not updates:
        return False

    values.append(session_id)

    with connect(db_path) as conn:
        cursor = conn.execute(
            f"UPDATE live_sessions SET {', '.join(updates)} "
            "WHERE session_id=?",
            values,
        )

        return cursor.rowcount > 0


def save_live_observation(
    session_id: str,
    observation: dict,
    db_path: str = DB_PATH,
) -> bool:
    mac = normalize_mac(observation.get("mac", ""))

    if not mac:
        return False

    now = observation.get("timestamp") or _now()

    with connect(db_path) as conn:
        existing = conn.execute("""
        SELECT *
        FROM live_observations
        WHERE session_id=? AND mac=?
        """, (
            session_id,
            mac,
        )).fetchone()

        if existing:
            old = dict(existing)

            protocols = set(_load(old["protocols"]))
            protocols.update(observation.get("protocols", []))

            ports = set(_load(old["ports"]))
            ports.update(observation.get("ports", []))

            dns_names = set(_load(old["dns_names"]))
            dns_names.update(observation.get("dns_names", []))

            conn.execute("""
            UPDATE live_observations SET
                ip=?,
                hostname=?,
                protocols=?,
                ports=?,
                dns_names=?,
                source=?,
                last_seen=?,
                observation_count=observation_count + 1
            WHERE session_id=? AND mac=?
            """, (
                observation.get("ip") or old["ip"],
                observation.get("hostname") or old["hostname"],
                _dump(sorted(protocols)),
                _dump(sorted(ports)),
                _dump(sorted(dns_names)),
                observation.get("source", "live_network"),
                now,
                session_id,
                mac,
            ))

        else:
            conn.execute("""
            INSERT INTO live_observations
            (
                session_id, mac, ip, hostname,
                protocols, ports, dns_names, source,
                first_seen, last_seen, observation_count
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                mac,
                observation.get("ip"),
                observation.get("hostname"),
                _dump(observation.get("protocols", [])),
                _dump(observation.get("ports", [])),
                _dump(observation.get("dns_names", [])),
                observation.get("source", "live_network"),
                now,
                now,
                1,
            ))

    return True


def get_live_observations(
    session_id: str,
    db_path: str = DB_PATH,
) -> list[dict]:
    with connect(db_path) as conn:
        rows = conn.execute("""
        SELECT *
        FROM live_observations
        WHERE session_id=?
        ORDER BY last_seen DESC
        """, (session_id,)).fetchall()

    items = []

    for row in rows:
        item = dict(row)

        for key in ("protocols", "ports", "dns_names"):
            item[key] = _load(item[key])

        items.append(item)

    return items


def get_live_session(
    session_id: str,
    db_path: str = DB_PATH,
) -> dict | None:
    with connect(db_path) as conn:
        row = conn.execute("""
        SELECT *
        FROM live_sessions
        WHERE session_id=?
        """, (session_id,)).fetchone()

    if not row:
        return None

    session = dict(row)

    session["devices"] = get_live_observations(
        session_id,
        db_path,
    )

    session["device_count"] = len(session["devices"])

    return session


def get_live_sessions(
    limit: int = 50,
    db_path: str = DB_PATH,
) -> list[dict]:
    with connect(db_path) as conn:
        rows = conn.execute("""
        SELECT *
        FROM live_sessions
        ORDER BY created_at DESC
        LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


def delete_live_session(
    session_id: str,
    db_path: str = DB_PATH,
) -> bool:
    with connect(db_path) as conn:
        cursor = conn.execute(
            "DELETE FROM live_sessions WHERE session_id=?",
            (session_id,),
        )

        return cursor.rowcount > 0
