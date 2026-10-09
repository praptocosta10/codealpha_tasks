# =============================================================================
# NIDS Dashboard — Streamlit Application
# =============================================================================
# A lightweight, real-time dashboard for visualizing Suricata IDS alerts.
# Reads eve.json (JSONL format) and displays charts, metrics, and tables.
#
# Usage:
#   streamlit run dashboard\app.py
#
# Opens at: http://localhost:8501
# =============================================================================

import os
import json
import time
from datetime import datetime, timedelta
from collections import Counter

import streamlit as st
import pandas as pd
import altair as alt

# =============================================================================
# Page Configuration
# =============================================================================
st.set_page_config(
    page_title="NIDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# =============================================================================
# Default Paths
# =============================================================================
DEFAULT_EVE_PATH = r"C:\NIDS\logs\eve.json"

# =============================================================================
# Sidebar Controls
# =============================================================================
st.sidebar.title("🛡️ NIDS Controls")
st.sidebar.markdown("---")

eve_path = st.sidebar.text_input("Eve.json Path", value=DEFAULT_EVE_PATH)
auto_refresh = st.sidebar.checkbox("Auto-refresh", value=True)
refresh_interval = st.sidebar.slider("Refresh interval (seconds)", 5, 60, 10)
severity_filter = st.sidebar.multiselect(
    "Severity Filter",
    options=[1, 2, 3, 4],
    default=[1, 2, 3, 4],
    format_func=lambda x: {1: "1 — High", 2: "2 — Medium", 3: "3 — Low", 4: "4 — Info"}.get(x, str(x)),
)
max_alerts = st.sidebar.number_input("Max alerts to load", min_value=100, max_value=100000, value=10000, step=1000)

if st.sidebar.button("🔄 Refresh Now"):
    st.cache_data.clear()
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown(
    "**NIDS Project** — Network Intrusion Detection System\n\n"
    "Built with [Suricata](https://suricata.io) + [Streamlit](https://streamlit.io)"
)


# =============================================================================
# Data Loading
# =============================================================================
@st.cache_data(ttl=10)
def load_alerts(path: str, max_lines: int = 10000) -> pd.DataFrame:
    """
    Load alert events from Suricata's eve.json (JSONL format).
    Only loads the last `max_lines` lines for performance.
    Returns a pandas DataFrame with alert fields.
    """
    if not os.path.exists(path):
        return pd.DataFrame()

    alerts = []

    try:
        # For large files, read only the last N lines efficiently
        file_size = os.path.getsize(path)
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            if file_size > 10 * 1024 * 1024:  # > 10 MB
                # Estimate bytes to read (avg ~500 bytes per line)
                seek_pos = max(0, file_size - (max_lines * 500))
                f.seek(seek_pos)
                f.readline()  # Skip partial first line
            lines = f.readlines()[-max_lines:]

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    alert_info = event.get("alert", {})
                    alerts.append({
                        "timestamp": event.get("timestamp", ""),
                        "src_ip": event.get("src_ip", ""),
                        "src_port": event.get("src_port", 0),
                        "dest_ip": event.get("dest_ip", ""),
                        "dest_port": event.get("dest_port", 0),
                        "proto": event.get("proto", ""),
                        "signature": alert_info.get("signature", ""),
                        "signature_id": alert_info.get("signature_id", 0),
                        "severity": alert_info.get("severity", 4),
                        "category": alert_info.get("category", ""),
                        "action": alert_info.get("action", ""),
                    })
            except json.JSONDecodeError:
                continue  # Skip malformed lines

    except Exception as e:
        st.error(f"Error reading eve.json: {e}")
        return pd.DataFrame()

    if not alerts:
        return pd.DataFrame()

    df = pd.DataFrame(alerts)

    # Parse timestamps
    try:
        df["timestamp"] = pd.to_datetime(df["timestamp"], format="mixed", utc=True)
    except Exception:
        try:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        except Exception:
            pass

    return df


# =============================================================================
# Main Dashboard
# =============================================================================
st.title("🛡️ NIDS Dashboard — Network Intrusion Detection System")
st.markdown("Real-time visualization of Suricata IDS alerts")
st.markdown("---")

# Load data
df = load_alerts(eve_path, max_lines=max_alerts)

# Check if eve.json exists
if not os.path.exists(eve_path):
    st.warning(
        f"⚠️ **Eve.json not found** at `{eve_path}`\n\n"
        "Start Suricata first:\n"
        "```powershell\n"
        "powershell -ExecutionPolicy Bypass -File C:\\NIDS\\scripts\\start-ids.ps1\n"
        "```"
    )
    st.stop()

if df.empty:
    st.info("📭 **No alerts yet.** Suricata is running but no alerts have been triggered. Run the test scripts to generate alerts.")
    st.stop()

# Apply severity filter
df_filtered = df[df["severity"].isin(severity_filter)]

if df_filtered.empty:
    st.info(f"No alerts match the selected severity filter: {severity_filter}")
    st.stop()


# =============================================================================
# Key Metrics Row
# =============================================================================
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("🚨 Total Alerts", len(df_filtered))

with col2:
    st.metric("🌐 Unique Source IPs", df_filtered["src_ip"].nunique())

with col3:
    st.metric("📋 Unique Signatures", df_filtered["signature"].nunique())

with col4:
    high_sev = len(df_filtered[df_filtered["severity"] <= 2])
    st.metric("🔴 High Severity", high_sev)

st.markdown("---")


# =============================================================================
# Alerts Over Time (Line Chart)
# =============================================================================
st.subheader("📈 Alerts Over Time")

if pd.api.types.is_datetime64_any_dtype(df_filtered["timestamp"]):
    time_df = df_filtered.copy()
    # Choose grouping based on time range
    time_range = time_df["timestamp"].max() - time_df["timestamp"].min()
    if time_range > timedelta(hours=6):
        time_df["time_bucket"] = time_df["timestamp"].dt.floor("h")
        time_label = "Hour"
    else:
        time_df["time_bucket"] = time_df["timestamp"].dt.floor("min")
        time_label = "Minute"

    time_counts = time_df.groupby("time_bucket").size().reset_index(name="count")
    time_counts.columns = ["Time", "Alert Count"]

    chart = (
        alt.Chart(time_counts)
        .mark_area(opacity=0.6, color="#ff4b4b", line={"color": "#ff4b4b"})
        .encode(
            x=alt.X("Time:T", title=f"Time ({time_label})"),
            y=alt.Y("Alert Count:Q", title="Alerts"),
            tooltip=["Time:T", "Alert Count:Q"],
        )
        .properties(height=300)
        .interactive()
    )
    st.altair_chart(chart, use_container_width=True)
else:
    st.info("Timestamps could not be parsed for time-series chart.")

st.markdown("---")


# =============================================================================
# Two-Column Layout: Top Source IPs & Top Signatures
# =============================================================================
col_left, col_right = st.columns(2)

with col_left:
    st.subheader("🌐 Top 10 Source IPs")
    top_ips = df_filtered["src_ip"].value_counts().head(10).reset_index()
    top_ips.columns = ["Source IP", "Count"]

    ip_chart = (
        alt.Chart(top_ips)
        .mark_bar(color="#ff6f61")
        .encode(
            x=alt.X("Count:Q", title="Alert Count"),
            y=alt.Y("Source IP:N", sort="-x", title=""),
            tooltip=["Source IP", "Count"],
        )
        .properties(height=350)
    )
    st.altair_chart(ip_chart, use_container_width=True)

with col_right:
    st.subheader("📋 Top 10 Signatures")
    top_sigs = df_filtered["signature"].value_counts().head(10).reset_index()
    top_sigs.columns = ["Signature", "Count"]

    sig_chart = (
        alt.Chart(top_sigs)
        .mark_bar(color="#4ecdc4")
        .encode(
            x=alt.X("Count:Q", title="Alert Count"),
            y=alt.Y("Signature:N", sort="-x", title=""),
            tooltip=["Signature", "Count"],
        )
        .properties(height=350)
    )
    st.altair_chart(sig_chart, use_container_width=True)

st.markdown("---")


# =============================================================================
# Severity Breakdown (Donut Chart)
# =============================================================================
st.subheader("⚠️ Severity Breakdown")

severity_labels = {1: "High (1)", 2: "Medium (2)", 3: "Low (3)", 4: "Info (4)"}
severity_colors = {"High (1)": "#e74c3c", "Medium (2)": "#f39c12", "Low (3)": "#f1c40f", "Info (4)": "#3498db"}

sev_counts = df_filtered["severity"].value_counts().reset_index()
sev_counts.columns = ["Severity", "Count"]
sev_counts["Label"] = sev_counts["Severity"].map(severity_labels)

donut = (
    alt.Chart(sev_counts)
    .mark_arc(innerRadius=60, outerRadius=120)
    .encode(
        theta=alt.Theta("Count:Q"),
        color=alt.Color(
            "Label:N",
            scale=alt.Scale(
                domain=list(severity_colors.keys()),
                range=list(severity_colors.values()),
            ),
            legend=alt.Legend(title="Severity"),
        ),
        tooltip=["Label:N", "Count:Q"],
    )
    .properties(width=400, height=300)
)
col_donut, col_stats = st.columns([1, 1])
with col_donut:
    st.altair_chart(donut, use_container_width=True)
with col_stats:
    st.markdown("#### Alert Statistics")
    for _, row in sev_counts.iterrows():
        pct = (row["Count"] / len(df_filtered)) * 100
        st.markdown(f"- **{row['Label']}**: {row['Count']} alerts ({pct:.1f}%)")

st.markdown("---")


# =============================================================================
# Recent Alerts Table
# =============================================================================
st.subheader("📃 Recent Alerts (Last 50)")

recent = df_filtered.sort_values("timestamp", ascending=False).head(50)
display_cols = ["timestamp", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "signature", "severity", "category"]
available_cols = [c for c in display_cols if c in recent.columns]

st.dataframe(
    recent[available_cols],
    use_container_width=True,
    height=500,
    column_config={
        "timestamp": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss"),
        "src_ip": "Source IP",
        "src_port": "Src Port",
        "dest_ip": "Dest IP",
        "dest_port": "Dst Port",
        "proto": "Protocol",
        "signature": st.column_config.TextColumn("Signature", width="large"),
        "severity": st.column_config.NumberColumn("Severity", format="%d"),
        "category": "Category",
    },
)


# =============================================================================
# Auto-Refresh
# =============================================================================
if auto_refresh:
    time.sleep(refresh_interval)
    st.rerun()
