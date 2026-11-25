
from __future__ import annotations

import io

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from shadowshield.storage import (
    init_db,
    get_approved_inventory,
    upsert_approved,
    delete_approved,
    get_analyses,
    get_analysis,
    get_recent_alerts,
    get_live_sessions,
    get_live_session,
)

from shadowshield.service import analyze_file
from shadowshield.normalize import normalize_mac
from shadowshield.graph import build_device_graph, graph_to_dict
from shadowshield.detection import analyze_devices

from shadowshield.live_schemas import LiveSessionCreate
from shadowshield.live_service import LiveDiscoveryService


app = FastAPI(
    title="ShadowShield API",
    version="1.2.0",
    description="Authorized network analysis and live device discovery API."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

live_service = LiveDiscoveryService()


@app.on_event("startup")
def startup():
    init_db()


class InventoryDevice(BaseModel):
    mac: str
    ip: str = ""
    hostname: str = ""
    vendor: str = ""
    ports: list[str] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    allowed_ports: list[str] = Field(default_factory=list)


# --------------------------------------------------
# HEALTH
# --------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "ShadowShield API"
    }


# --------------------------------------------------
# APPROVED DEVICE INVENTORY
# --------------------------------------------------

@app.get("/api/inventory")
def list_inventory():
    return {
        "devices": list(get_approved_inventory().values())
    }


@app.post("/api/inventory")
def add_inventory(device: InventoryDevice):
    payload = device.model_dump()
    payload["mac"] = normalize_mac(payload["mac"])

    if not payload["mac"]:
        raise HTTPException(
            status_code=400,
            detail="MAC address is required."
        )

    try:
        upsert_approved(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "message": "Approved device saved",
        "device": get_approved_inventory()[payload["mac"]]
    }


@app.delete("/api/inventory/{mac}")
def remove_inventory(mac: str):
    normalized = normalize_mac(mac)

    if not normalized:
        raise HTTPException(
            status_code=400,
            detail="Invalid MAC address."
        )

    if not delete_approved(normalized):
        raise HTTPException(
            status_code=404,
            detail="Approved device not found."
        )

    return {
        "message": "Approved device removed",
        "mac": normalized
    }


# --------------------------------------------------
# CSV ANALYSIS
# --------------------------------------------------

@app.post("/api/analyze/csv")
async def analyze_csv(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Upload a .csv file."
        )

    content = await file.read()

    try:
        return analyze_file(
            io.BytesIO(content),
            file.filename,
            "csv"
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc)
        )

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"CSV analysis failed: {exc}"
        )


# --------------------------------------------------
# PCAP ANALYSIS
# --------------------------------------------------

@app.post("/api/analyze/pcap")
async def analyze_pcap(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(
        (".pcap", ".pcapng")
    ):
        raise HTTPException(
            status_code=400,
            detail="Upload a .pcap or .pcapng file."
        )

    content = await file.read()

    try:
        return analyze_file(
            io.BytesIO(content),
            file.filename,
            "pcap"
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc)
        )

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"PCAP analysis failed: {exc}"
        )


# --------------------------------------------------
# ANALYSIS HISTORY
# --------------------------------------------------

@app.get("/api/analyses")
def list_analyses(limit: int = 50):
    return {
        "analyses": get_analyses(max(1, min(limit, 200)))
    }


@app.get("/api/analyses/{analysis_id}")
def analysis_detail(analysis_id: str):
    item = get_analysis(analysis_id)

    if not item:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found."
        )

    return item


# --------------------------------------------------
# ALERTS
# --------------------------------------------------

@app.get("/api/alerts")
def list_alerts(limit: int = 100):
    return {
        "alerts": get_recent_alerts(max(1, min(limit, 500)))
    }


# --------------------------------------------------
# HISTORICAL ANALYSIS GRAPH
# --------------------------------------------------

@app.get("/api/graph/latest")
def latest_graph():
    analyses = get_analyses(limit=1)

    if not analyses:
        return {
            "nodes": [],
            "edges": []
        }

    detail = get_analysis(analyses[0]["id"])
    graph = build_device_graph(detail.get("results", []))

    return graph_to_dict(graph)


# --------------------------------------------------
# LIVE NETWORK DISCOVERY
# --------------------------------------------------

@app.post("/api/live/sessions")
def create_live_session(request: LiveSessionCreate):
    try:
        return live_service.create_session(
            interface=request.interface,
            subnet=request.subnet
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc)
        )

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Could not create live session: {exc}"
        )


@app.post("/api/live/sessions/{session_id}/start")
def start_live_session(session_id: str):
    try:
        return live_service.start_session(session_id)

    except KeyError:
        raise HTTPException(
            status_code=404,
            detail="Live session not found in this API process."
        )

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Could not start live discovery: {exc}"
        )


@app.post("/api/live/sessions/{session_id}/stop")
def stop_live_session(session_id: str):
    try:
        return live_service.stop_session(session_id)

    except KeyError:
        raise HTTPException(
            status_code=404,
            detail="Live session not found in this API process."
        )

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Could not stop live discovery: {exc}"
        )


@app.get("/api/live/sessions")
def list_live_sessions(limit: int = 50):
    return {
        "sessions": get_live_sessions(max(1, min(limit, 200)))
    }


@app.get("/api/live/sessions/{session_id}")
def live_session_detail(session_id: str):
    session = get_live_session(session_id)

    if not session:
        raise HTTPException(
            status_code=404,
            detail="Live session not found."
        )

    return session


@app.get("/api/live/sessions/{session_id}/devices")
def live_session_devices(session_id: str):
    session = get_live_session(session_id)

    if not session:
        raise HTTPException(
            status_code=404,
            detail="Live session not found."
        )

    return {
        "session_id": session_id,
        "device_count": session.get("device_count", 0),
        "devices": session.get("devices", [])
    }


# --------------------------------------------------
# APPROVE A LIVE DISCOVERED DEVICE
# --------------------------------------------------

@app.post("/api/live/sessions/{session_id}/devices/{mac}/approve")
def approve_live_device(session_id: str, mac: str):
    normalized_mac = normalize_mac(mac)

    if not normalized_mac:
        raise HTTPException(
            status_code=400,
            detail="Invalid MAC address."
        )

    session = get_live_session(session_id)

    if not session:
        raise HTTPException(
            status_code=404,
            detail="Live session not found."
        )

    observed_device = next(
        (
            device
            for device in session.get("devices", [])
            if normalize_mac(device.get("mac", "")) == normalized_mac
        ),
        None
    )

    if observed_device is None:
        raise HTTPException(
            status_code=404,
            detail="Device was not observed in this live session."
        )

    if not (
        observed_device.get("ip")
        or observed_device.get("hostname")
        or observed_device.get("vendor")
    ):
        raise HTTPException(
            status_code=400,
            detail="Insufficient device identity information for approval."
        )

    approved_device = {
        "mac": normalized_mac,
        "ip": observed_device.get("ip") or "",
        "hostname": observed_device.get("hostname") or "",
        "vendor": observed_device.get("vendor") or "",
        "ports": [],
        "protocols": observed_device.get("protocols", []),
        "allowed_ports": []
    }

    try:
        upsert_approved(approved_device)

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc)
        )

    saved_device = get_approved_inventory().get(normalized_mac)

    return {
        "message": "Device approved successfully.",
        "session_id": session_id,
        "device": saved_device,
        "note": (
            "Live traffic ports were excluded from the approved "
            "fingerprint because they do not establish listening services."
        )
    }


# --------------------------------------------------
# LIVE NETWORK ANALYSIS
# --------------------------------------------------

@app.get("/api/live/sessions/{session_id}/analysis")
def analyze_live_session(session_id: str):
    session = get_live_session(session_id)

    if not session:
        raise HTTPException(
            status_code=404,
            detail="Live session not found."
        )

    devices = session.get("devices", [])

    normalized_devices = []

    for device in devices:
        observed = dict(device)
        observed["source"] = "live_network"
        normalized_devices.append(observed)

    approved_inventory = get_approved_inventory()

    results = analyze_devices(
        normalized_devices,
        approved_inventory
    )

    graph = build_device_graph(results)

    counts = {
        "total": len(results),
        "known": sum(item["status"] == "Known" for item in results),
        "unknown": sum(item["status"] == "Unknown" for item in results),
        "changed": sum(item["status"] == "Changed" for item in results),
        "insufficient_evidence": sum(
            item["status"] == "Insufficient Evidence"
            for item in results
        ),
        "high_risk": sum(
            item["risk_score"] >= 60 for item in results
        ),
        "medium_risk": sum(
            30 <= item["risk_score"] < 60 for item in results
        ),
        "low_risk": sum(
            item["risk_score"] < 30 for item in results
        )
    }

    return {
        "session_id": session_id,
        "session_status": session.get("status"),
        "counts": counts,
        "results": results,
        "graph": graph_to_dict(graph)
    }
