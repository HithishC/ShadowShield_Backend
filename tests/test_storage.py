from shadowshield.storage import init_db, upsert_approved, get_approved_inventory, delete_approved

def test_inventory_crud(tmp_path):
    db = str(tmp_path / "test.db")
    init_db(db)
    device = {"mac":"00:11:22:33:44:55","ip":"10.0.0.5","hostname":"test","vendor":"x","ports":["443"],"protocols":["TCP"],"allowed_ports":["443"]}
    upsert_approved(device, db)
    inventory = get_approved_inventory(db)
    assert "00:11:22:33:44:55" in inventory
    assert delete_approved("00:11:22:33:44:55", db)
    assert not get_approved_inventory(db)
