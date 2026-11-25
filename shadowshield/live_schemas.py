
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class LiveSessionCreate(BaseModel):
    interface: str = Field(
        ...,
        min_length=1,
        description="Network interface selected for authorized discovery",
    )

    subnet: Optional[str] = Field(
        default=None,
        description="Optional authorized subnet in CIDR notation",
    )


class LiveSessionResponse(BaseModel):
    session_id: str
    interface: str
    subnet: Optional[str] = None
    status: str
    started_at: Optional[datetime] = None
    stopped_at: Optional[datetime] = None


class LiveObservation(BaseModel):
    mac: Optional[str] = None
    ip: Optional[str] = None
    hostname: Optional[str] = None

    protocols: list[str] = Field(default_factory=list)
    ports: list[str] = Field(default_factory=list)
    dns_names: list[str] = Field(default_factory=list)

    source: str = "live_network"
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class LiveSessionStatus(BaseModel):
    session_id: str
    status: str
    device_count: int = 0
    observations_count: int = 0
    devices: list[dict] = Field(default_factory=list)
