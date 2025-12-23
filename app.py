# app.py (patched, full file)
import os
import time
import math
import streamlit as st
import plotly.graph_objects as go
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
from streamlit_autorefresh import st_autorefresh
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode


# utils (assumes these modules exist in utils/)
from utils.ui_helpers import init_analyzers
from utils.report_generator import ReportGenerator

# ---------------------------------------------------------------------------
# Page configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="CyberSecure Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------------------------------------------------------------------
# Session state defaults
# ---------------------------------------------------------------------------
if 'threat_level' not in st.session_state:
    st.session_state.threat_level = 'LOW'
if 'total_scans' not in st.session_state:
    st.session_state.total_scans = 0
if 'threats_detected' not in st.session_state:
    st.session_state.threats_detected = 0
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []
if 'scan_message' not in st.session_state:
    st.session_state.scan_message = "Ready for action 🧠"
if 'threat_stats' not in st.session_state:
    st.session_state.threat_stats = {"Clean Files": 0, "Threats Detected": 0}
if 'scanned_files_cache' not in st.session_state:
    st.session_state.scanned_files_cache = set()
if 'scan_path' not in st.session_state:
    default_scan_path = os.path.join(os.path.expanduser("~"), "Downloads")
    st.session_state.scan_path = os.environ.get("DEFAULT_SCAN_PATH", default_scan_path)

# ---------------------------------------------------------------------------
# Load external CSS
# ---------------------------------------------------------------------------
def load_css(file_name):
    with open(file_name) as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

load_css("assets/style.css")

# ---------------------------------------------------------------------------
# Initialize analyzer utilities
# ---------------------------------------------------------------------------
analyzers = init_analyzers() or {}

# ---------------------------------------------------------------------------
# Visual helpers
# ---------------------------------------------------------------------------
def create_threat_level_indicator():
    """Dynamic threat level gauge with pulsing when CRITICAL"""
    level_colors = {
        'LOW': '#28a745',
        'MEDIUM': '#ffc107',
        'HIGH': '#fd7e14',
        'CRITICAL': '#dc3545'
    }

    # Base color
    base_color = level_colors.get(st.session_state.threat_level, '#28a745')

    # Pulse red when CRITICAL by modulating the RGB channels a bit
    if st.session_state.threat_level == 'CRITICAL':
        # produce an animated red tint using a sine wave
        t = time.time()
        # value oscillates 0..1
        pulse = (math.sin(t * 3.0) + 1) / 2.0
        # produce a brighter red at pulse times
        r = 255
        g = int(50 + pulse * 80)   # vary green channel up a bit
        b = int(50 + pulse * 80)
        base_color = f"rgb({r},{g},{b})"

    value_map = {'LOW': 25, 'MEDIUM': 50, 'HIGH': 75, 'CRITICAL': 100}
    value = value_map.get(st.session_state.threat_level, 25)

    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=value,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Threat Level"},
        delta={'reference': 25},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': base_color},
            'steps': [
                {'range': [0, 25], 'color': "#e9f7ef"},
                {'range': [25, 50], 'color': "#fff3cd"},
                {'range': [50, 75], 'color': "#ffe5b4"},
                {'range': [75, 100], 'color': "#f8d7da"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    fig.update_layout(height=300, margin=dict(l=0, r=0, t=30, b=0))
    return fig

def create_dynamic_pie_chart():
    """Dynamic pie chart showing clean vs detected threats in real-time"""
    # Update threat_stats based on current session
    st.session_state.threat_stats["Threats Detected"] = st.session_state.threats_detected
    st.session_state.threat_stats["Clean Files"] = max(0, st.session_state.total_scans - st.session_state.threats_detected)

    labels = list(st.session_state.threat_stats.keys())
    values = list(st.session_state.threat_stats.values())

    # if no scans yet, show neutral slice
    if sum(values) == 0:
        values = [1, 0]  # avoid empty pie

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.4,
        marker_colors=["#28a745", "#dc3545"],
        sort=False
    )])

    fig.update_traces(
        hoverinfo='label+percent',
        textinfo='label+value',
        textfont_size=14,
        pull=[0, 0.08]  # slight pull for threat slice
    )
    fig.update_layout(
        title_text="Real-time Threat Distribution",
        height=350,
        margin=dict(l=0, r=0, t=30, b=0)
    )
    return fig

def create_security_metrics_chart():
    """Sample security metrics time-series (demo only)"""
    dates = pd.date_range(start=datetime.now() - timedelta(days=7), end=datetime.now(), freq='h')
    np.random.seed(42)
    scans_data = np.random.poisson(3, len(dates))
    threats_data = np.random.poisson(0.5, len(dates))
    df = pd.DataFrame({
        'timestamp': dates,
        'scans': scans_data,
        'threats': threats_data,
        'clean_files': scans_data - threats_data
    })
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=df['timestamp'], y=df['scans'], mode='lines+markers', name='Total Scans'))
    fig.add_trace(go.Scatter(x=df['timestamp'], y=df['threats'], mode='lines+markers', name='Threats Detected'))
    fig.add_trace(go.Scatter(x=df['timestamp'], y=df['clean_files'], mode='lines+markers', name='Clean Files'))
    fig.update_layout(title='Security Activity Over Time', xaxis_title='Time', yaxis_title='Count', height=400, hovermode='x unified')
    return fig

# ---------------------------------------------------------------------------
# Sidebar: Folder Selection & Emergency Scan (Patched)
# ---------------------------------------------------------------------------
def sidebar_controls():
    st.sidebar.header("📂 Scan Folder & Quick Actions")

    # Detect current user home directory
    import os
    user_home = os.path.expanduser("~")

    # Quick-select common folders (portable)
    common_dirs = [
        os.path.join(user_home, "Downloads"),
        os.path.join(user_home, "Documents"),
        os.path.join(user_home, "Desktop"),
        os.path.join(user_home, "Music"),
        os.path.join(user_home, "Pictures"),
        os.path.join(user_home, "Gallery"),
        "C:\\Program Files",
        "C:\\Windows\\Temp"
    ]
    # Keep only existing folders
    common_dirs = [d for d in common_dirs if os.path.exists(d)]

    selected_common = st.sidebar.selectbox(
        "Quick select common folders:",
        options=["-- Select --"] + common_dirs,
        index=0
    )
    if selected_common != "-- Select --":
        st.session_state.scan_path = selected_common
        st.sidebar.success(f"Folder selected: {selected_common}")

    # Manual path input (retain previous)
    manual_path = st.sidebar.text_input("Or enter custom folder path:", value=st.session_state.scan_path)
    if manual_path and manual_path != st.session_state.scan_path:
        st.session_state.scan_path = manual_path

    # Current folder info
    st.sidebar.info(f"Current Scan Folder:\n`{st.session_state.scan_path}`")
    if not os.path.exists(st.session_state.scan_path):
        st.sidebar.warning(f"⚠️ Path does not exist: {st.session_state.scan_path}")

    st.sidebar.markdown("---")
    st.sidebar.info(st.session_state.get("scan_message", "Ready for action 🧠"))

    # Emergency Scan button
    if st.sidebar.button("🚨 Emergency Scan", use_container_width=True, type="primary"):
        if 'file_analyzer' not in analyzers:
            st.sidebar.warning("⚠️ File analyzer not available.")
            return

        st.session_state["scan_message"] = f"🕵️ Running emergency scan on: `{st.session_state.scan_path}`"
        st.toast("🚨 Emergency scan initiated", icon="🛡️")

        try:
            # Run hybrid scan (live updates & caching)
            result = analyzers['file_analyzer'].scan_system_hybrid(root_path=st.session_state.scan_path)

            st.session_state["scan_message"] = result if isinstance(result, str) else str(result)
            st.toast("✅ Emergency scan completed", icon="🟢")
            st.sidebar.success(st.session_state["scan_message"])
        except Exception as e:
            st.session_state["scan_message"] = f"Scan failed: {e}"
            st.sidebar.error(st.session_state["scan_message"])

        # ✅ Updated: replaced deprecated experimental_rerun
        st.rerun()


# ---------------------------------------------------------------------------
# Main layout
# ---------------------------------------------------------------------------
def main():
    # auto refresh small interval so pulsing gauge animates and UI stays fresh
    refresh_rate = st.sidebar.slider("⏱️ Auto-refresh every (seconds)", 2, 30, 6)
    st_autorefresh(interval=refresh_rate * 1000, key="auto_refresh_timer")

    st.markdown(
        "<div style='background-color:#0f1117;padding:18px;border-radius:10px;text-align:center'>"
        "<h1 style='color:#00FF9D;margin:0;'>🛡️ AegisGuardAI</h1>"
        "<p style='color:#ccc;margin:0;'>Autonomous Cyber Defense & Threat Intelligence Suite</p>"
        "</div>",
        unsafe_allow_html=True
    )
    st.divider()
    st.title("🛡️ CyberSecure Dashboard")
    st.divider()
    st.markdown("### Comprehensive AI-Powered Security Monitoring")

    # Sidebar controls
    sidebar_controls()

    # Analyzer availability check
    if not analyzers:
        st.error("⚠️ Analyzer initialization failed. Please verify your utils modules.")
        st.stop()

    # Top row: metrics and visualizations
    col1, col2, col3 = st.columns([2, 1, 2])

    with col1:
        st.subheader("Security Metrics Overview")
        fig_pie = create_dynamic_pie_chart()
        st.plotly_chart(
            fig_pie,
            config={"responsive": True},  # ✅ official replacement for old args
        )

    with col2:
        st.subheader("Current Threat Level")
        fig_gauge = create_threat_level_indicator()
        st.plotly_chart(
            fig_gauge,
            config={"responsive": True},  # ✅ future-proofed
        )

    # ---------------------------------------------------------------------------
    # Simple Edition
    # ---------------------------------------------------------------------------
    # ---------------------------------------------------------------------------
    # Simple Edition (Dark Hacker Style)
    # ---------------------------------------------------------------------------
    with col3:
        st.subheader("All Detected Threats")

        # Build DataFrame of all threats
        recent_threats = [entry for entry in st.session_state.scan_history if "⚠️" in entry.get('details', '')]

        if recent_threats:
            df_threats = pd.DataFrame(recent_threats)

            # Split details into file and status
            def split_details(d):
                if '⚠️' in d:
                    parts = d.split('⚠️', 1)
                    return parts[0].strip(), '⚠️ Threat Detected'
                if '✅' in d:
                    parts = d.split('✅', 1)
                    return parts[0].strip(), '✅ Clean'
                return d, ''

            df_threats[['File', 'Status']] = df_threats['details'].apply(lambda x: pd.Series(split_details(x)))
            display_df = df_threats[['time', 'File', 'Status', 'action']].copy()
            display_df.rename(columns={'time': 'Time', 'action': 'Action'}, inplace=True)

            # Add numbering
            display_df.index = np.arange(1, len(display_df) + 1)
            display_df.index.name = "No."

            # ✅ Display the dark-mode table
            #st.dataframe(display_df, width='stretch', height=350)
            st.dataframe(display_df, width=800, height=350)

        else:
            st.markdown("""
            <div style="
                background-color:#0d1117;
                border:1px solid #222831;
                border-radius:10px;
                padding:20px;
                text-align:center;
                color:#39ff14;
                font-family:'Courier New', monospace;
                font-size:16px;">
                ✅ No threats detected yet. Your system is secure.
            </div>
            """, unsafe_allow_html=True)

    # Quick stats row
    st.divider()
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Files Scanned Today", value=st.session_state.total_scans,
                  delta=f"+{np.random.randint(1, 10)} from yesterday")
    with col2:
        st.metric("Threats Blocked", value=st.session_state.threats_detected,
                  delta=f"+{np.random.randint(0, 3)} from yesterday")
    with col3:
        st.metric("Active Connections", value=np.random.randint(50, 150),
                  delta=f"+{np.random.randint(-10, 20)} from last hour")
    with col4:
        uptime_hours = np.random.randint(1, 24)
        st.metric("System Uptime", value=f"{uptime_hours}h", delta="Running smoothly")

    # Alerts
    st.divider()
    st.subheader("🚨 Recent Security Alerts")
    alert_col1, alert_col2 = st.columns(2)
    with alert_col1:
        st.warning("**Medium Priority Alert**")
        st.write("Suspicious network activity detected from IP: 192.168.1.xxx")
        st.write("*2 minutes ago*")
    with alert_col2:
        st.info("**System Update**")
        st.write("Threat intelligence database updated successfully")
        st.write("*15 minutes ago*")

    # Footer
    st.divider()
    st.markdown("""
    ### 🔍 Explore More Features:
    - **📁 File Analysis** – Upload and analyze files for malware  
    - **🌐 Network Analysis** – Monitor network traffic and detect anomalies  
    - **🔍 Threat Intelligence** – Check IPs/domains/hashes against global threat databases  
    - **📊 Security Reports** – Generate detailed security reports  
    """, unsafe_allow_html=True)
    st.divider()

if __name__ == "__main__":
    main()
