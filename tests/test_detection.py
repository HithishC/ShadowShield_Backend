import pandas as pd
from shadowshield.normalize import normalize_observations
from shadowshield.discovery import aggregate_devices
from shadowshield.detection import analyze_devices

def test_sample_counts_and_statuses():
    frame = pd.DataFrame([
        {"mac":"00:11:22:33:44:01","ip":"10.0.0.1","hostname":"alpha","vendor":"v","ports":"443","protocols":"TCP"},
        {"mac":"00:11:22:33:44:02","ip":"10.0.0.2","hostname":"beta","vendor":"v","ports":"22,443","protocols":"TCP"},
        {"mac":"02:aa:bb:cc:dd:ee","ip":"10.0.0.3","hostname":"new","vendor":"x","ports":"23","protocols":"TCP"},
        {"mac":"00:11:22:33:44:02","ip":"10.0.0.2","hostname":"beta","vendor":"v","ports":"22,443,3389","protocols":"TCP"},
    ])
    normalized = normalize_observations(frame)
    devices = aggregate_devices(normalized)
    approved = {
        "00:11:22:33:44:01": {"mac":"00:11:22:33:44:01","ip":"10.0.0.1","hostname":"alpha","vendor":"v","ports":["443"],"protocols":["TCP"],"allowed_ports":["443"]},
        "00:11:22:33:44:02": {"mac":"00:11:22:33:44:02","ip":"10.0.0.2","hostname":"beta","vendor":"v","ports":["22","443"],"protocols":["TCP"],"allowed_ports":["22","443"]},
    }
    results = analyze_devices(devices, approved)
    statuses = {r["mac"]: r["status"] for r in results}
    assert statuses["00:11:22:33:44:01"] == "Known"
    assert statuses["00:11:22:33:44:02"] == "Changed"
    assert statuses["02:aa:bb:cc:dd:ee"] == "Unknown"

def test_missing_mac_column_rejected():
    try:
        normalize_observations(pd.DataFrame([{"ip":"10.0.0.1"}]))
    except ValueError as exc:
        assert "MAC" in str(exc)
    else:
        raise AssertionError("Expected missing MAC error")
