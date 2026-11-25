import streamlit as st
import pandas as pd
from shadowshield.storage import init_db, get_approved_inventory, upsert_approved, get_recent_alerts
from shadowshield.service import analyze_file

init_db()
st.set_page_config(page_title="ShadowShield", page_icon="🛡️", layout="wide")
st.title("🛡️ ShadowShield")
st.caption("Offline authorized network observation analysis")

page = st.sidebar.radio("Navigation", ["Dashboard", "Approved Inventory", "Analyze Data", "Alerts"])

def seed_demo():
    demo = [
        {"mac":"00:11:22:33:44:01","ip":"192.168.10.11","hostname":"pay-terminal-01","vendor":"DemoVendor","ports":["443"],"protocols":["TCP","DHCP"],"allowed_ports":["443"]},
        {"mac":"00:11:22:33:44:02","ip":"192.168.10.12","hostname":"branch-server-01","vendor":"DemoVendor","ports":["22","443"],"protocols":["TCP","DNS"],"allowed_ports":["22","443"]},
        {"mac":"00:11:22:33:44:03","ip":"192.168.10.13","hostname":"staff-laptop-01","vendor":"DemoVendor","ports":["443"],"protocols":["TCP","DHCP"],"allowed_ports":["443"]},
    ]
    for item in demo: upsert_approved(item)

if st.sidebar.button("Load demo inventory"):
    seed_demo()
    st.sidebar.success("Demo inventory loaded.")

if page == "Dashboard":
    inventory = get_approved_inventory()
    alerts = get_recent_alerts()
    result = st.session_state.get("latest_analysis", {})
    counts = result.get("counts", {})
    st.subheader("Overview")
    c1,c2,c3 = st.columns(3)
    c1.metric("Observed Devices", counts.get("total", 0))
    c2.metric("Approved Devices", len(inventory))
    c3.metric("Unknown Devices", counts.get("unknown", 0))
    c4,c5,c6 = st.columns(3)
    c4.metric("Changed Devices", counts.get("changed", 0))
    c5.metric("High Risk", counts.get("high_risk", 0))
    c6.metric("Stored Alerts", len(alerts))
    if result.get("results"):
        st.subheader("Latest Detection Results")
        st.dataframe(pd.DataFrame(result["results"]), use_container_width=True, hide_index=True)
    else:
        st.info("Go to Analyze Data and upload an authorized CSV or PCAP.")

elif page == "Approved Inventory":
    st.subheader("Approved Inventory")
    inventory = list(get_approved_inventory().values())
    if inventory:
        st.dataframe(pd.DataFrame(inventory), use_container_width=True, hide_index=True)
    with st.form("new_device"):
        mac = st.text_input("MAC address")
        ip = st.text_input("IP address")
        hostname = st.text_input("Hostname")
        vendor = st.text_input("Vendor")
        ports = st.text_input("Allowed ports (comma-separated)", "443")
        save = st.form_submit_button("Save device")
        if save:
            if not mac.strip():
                st.error("MAC address is required.")
            else:
                allowed = [x.strip() for x in ports.split(",") if x.strip()]
                upsert_approved({"mac":mac,"ip":ip,"hostname":hostname,"vendor":vendor,
                                 "ports":allowed,"protocols":[],"allowed_ports":allowed})
                st.success("Saved.")
                st.rerun()

elif page == "Analyze Data":
    uploaded = st.file_uploader("Upload CSV, PCAP, or PCAPNG", type=["csv","pcap","pcapng"])
    if uploaded:
        ext = uploaded.name.rsplit(".",1)[-1].lower()
        if st.button("Run detection", type="primary"):
            try:
                result = analyze_file(uploaded, uploaded.name, ext)
                st.session_state["latest_analysis"] = result
                st.success(f"Analyzed {result['counts']['total']} devices.")
            except Exception as exc:
                st.error(f"Analysis failed: {exc}")
        result = st.session_state.get("latest_analysis", {})
        if result.get("results"):
            st.subheader("Detection Results")
            st.dataframe(pd.DataFrame(result["results"]), use_container_width=True, hide_index=True)
            st.download_button("Download results CSV", pd.DataFrame(result["results"]).to_csv(index=False), "shadowshield_results.csv", "text/csv")
            st.subheader("Graph summary")
            st.write(f"{len(result['graph']['nodes'])} nodes, {len(result['graph']['edges'])} edges")

elif page == "Alerts":
    alerts = get_recent_alerts()
    st.subheader("Recent Alerts")
    if not alerts:
        st.info("No alerts yet.")
    for alert in alerts:
        with st.expander(f"{alert['status']} | {alert['mac']} | Risk {alert['risk_score']}/100"):
            st.write("Risk band:", alert["risk_band"])
            for reason in alert["reasons"]:
                st.write("- " + reason)
