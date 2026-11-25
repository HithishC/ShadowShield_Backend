# ShadowShield Backend

Offline, authorized network-observation analysis for the ShadowShield hackathon prototype.

## Stack
- Python: service and detection logic
- Scapy: offline PCAP/PCAPNG parsing (no live scanning)
- Pandas: CSV parsing and normalization
- SQLite: approved inventory, analysis history, observations, alerts
- NetworkX: graph generation
- FastAPI + Uvicorn: REST API for a future React/Google AI Studio frontend
- Streamlit: optional current demo UI (`streamlit_app.py`)

## Setup (Windows PowerShell)
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Start REST API
```powershell
uvicorn api:app --reload
```
API docs: http://127.0.0.1:8000/docs

## Start optional Streamlit demo
```powershell
streamlit run streamlit_app.py
```

## CSV format
Required: `mac` (aliases like `MAC Address` are accepted)
Optional: `ip`, `hostname`, `vendor`, `ports`, `protocols`, `seen_at`

`ports` and `protocols` can be comma- or semicolon-separated. Delimiter inference supports comma, semicolon, and tab. Save as UTF-8 CSV.

## API overview
- `GET /health`
- `GET /api/inventory`
- `POST /api/inventory`
- `DELETE /api/inventory/{mac}`
- `POST /api/analyze/csv` (multipart file)
- `POST /api/analyze/pcap` (multipart file)
- `GET /api/analyses`
- `GET /api/analyses/{analysis_id}`
- `GET /api/alerts`
- `GET /api/graph/latest`

## Safety / limits
Use only data you are authorized to analyze. PCAP is parsed offline; the application does not scan networks, probe devices, or access bank systems. A device cannot be discovered from a capture source if it produces no observable evidence there. Unknown means not in the approved inventory and is not proof of maliciousness.

The risk score is a configurable heuristic, not an attack probability. Default rules: unknown +30, unexpected port(s) +20, changed fingerprint +20, insufficient identity +10; score is clamped to 0-100.
