# pages/2_Network_Analysis.py
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import sys
import os
import json

# Add the project root to the path to import utilities
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.ui_helpers import init_analyzers
from utils.report_generator import ReportGenerator

# Page configuration
st.set_page_config(
    page_title="Network Analysis - CyberSecure Dashboard",
    page_icon="🌐",
    layout="wide"
)

def create_network_overview_charts(network_summary):
    """Create network overview visualizations"""
    charts = {}
    
    # Protocol distribution
    if 'protocol_distribution' in network_summary:
        proto_data = network_summary['protocol_distribution']
        if proto_data:
            fig_proto = px.pie(
                values=list(proto_data.values()),
                names=list(proto_data.keys()),
                title="Protocol Distribution"
            )
            charts['protocol'] = fig_proto
    
    # Top remote IPs
    if 'top_remote_ips' in network_summary:
        ip_data = network_summary['top_remote_ips']
        if ip_data:
            fig_ips = px.bar(
                x=list(ip_data.values()),
                y=list(ip_data.keys()),
                orientation='h',
                title="Top Remote IP Addresses",
                labels={'x': 'Connection Count', 'y': 'IP Address'}
            )
            charts['top_ips'] = fig_ips
    
    # Risk distribution
    if 'risk_distribution' in network_summary:
        risk_data = network_summary['risk_distribution']
        if any(risk_data.values()):
            fig_risk = px.bar(
                x=['Low Risk', 'Medium Risk', 'High Risk'],
                y=[risk_data.get('low_risk', 0), risk_data.get('medium_risk', 0), risk_data.get('high_risk', 0)],
                title="Connection Risk Distribution",
                color=['Low Risk', 'Medium Risk', 'High Risk'],
                color_discrete_map={'Low Risk': '#28a745', 'Medium Risk': '#ffc107', 'High Risk': '#dc3545'}
            )
            charts['risk'] = fig_risk
    
    return charts

def display_anomaly_details(anomalies):
    """Display detailed anomaly information"""
    if not anomalies.get('anomalies'):
        st.success("✅ No network anomalies detected")
        return
    
    st.warning(f"⚠️ {anomalies.get('anomaly_count', 0)} anomalies detected ({anomalies.get('anomaly_percentage', 0):.1f}% of connections)")
    
    # Group anomalies by type
    anomaly_types = {}
    for anomaly in anomalies['anomalies']:
        anomaly_type = anomaly.get('type', 'Unknown')
        if anomaly_type not in anomaly_types:
            anomaly_types[anomaly_type] = []
        anomaly_types[anomaly_type].append(anomaly)
    
    # Display each type of anomaly
    for anomaly_type, type_anomalies in anomaly_types.items():
        with st.expander(f"🚨 {anomaly_type.replace('_', ' ').title()} ({len(type_anomalies)} instances)", expanded=True):
            for i, anomaly in enumerate(type_anomalies, 1):
                severity = anomaly.get('severity', 'UNKNOWN')
                severity_color = {'HIGH': '🔴', 'MEDIUM': '🟠', 'LOW': '🟡'}.get(severity, '⚪')
                
                st.write(f"**{severity_color} Anomaly #{i} - Severity: {severity}**")
                
                if anomaly_type == 'port_scan':
                    st.write(f"- Source IP: `{anomaly.get('remote_ip', 'Unknown')}`")
                    st.write(f"- Ports scanned: {anomaly.get('port_count', 0)}")
                    st.write(f"- Total connections: {anomaly.get('connection_count', 0)}")
                
                elif anomaly_type == 'high_frequency':
                    st.write(f"- Time window: {anomaly.get('time_window', 'Unknown')}")
                    st.write(f"- Connection count: {anomaly.get('connection_count', 0)}")
                
                elif anomaly_type == 'high_outbound_data':
                    conn = anomaly.get('connection', {})
                    st.write(f"- Remote IP: `{conn.get('remote_ip', 'Unknown')}`")
                    st.write(f"- Data sent: {anomaly.get('bytes_sent', 0):,} bytes")
                
                elif anomaly_type == 'suspicious_geolocation':
                    st.write(f"- Connections count: {anomaly.get('count', 0)}")
                    countries = anomaly.get('countries', {})
                    if countries:
                        st.write("- Countries/Regions:")
                        for country, count in countries.items():
                            st.write(f"  - {country}: {count} connections")
                
                st.divider()

def display_ip_analysis_results(ip_results):
    """Display IP analysis results"""
    if not ip_results or 'results' not in ip_results:
        st.info("No IP analysis results available")
        return
    
    st.subheader("🌍 IP Address Analysis")
    
    summary = ip_results.get('summary', {})
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total IPs Analyzed", summary.get('successful', 0))
    with col2:
        st.metric("High Risk IPs", summary.get('high_risk', 0))
    with col3:
        st.metric("Medium Risk IPs", summary.get('medium_risk', 0))
    with col4:
        st.metric("Low Risk IPs", summary.get('low_risk', 0))
    
    # Display individual IP results
    results = ip_results.get('results', [])
    high_risk_ips = [r for r in results if r.get('risk_score', 0) >= 70]
    
    if high_risk_ips:
        st.warning(f"⚠️ {len(high_risk_ips)} high-risk IP addresses detected")
        
        for ip_result in high_risk_ips:
            with st.expander(f"🚨 High Risk IP: {ip_result.get('ip_address', 'Unknown')}", expanded=False):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**IP Information:**")
                    st.write(f"- Risk Score: {ip_result.get('risk_score', 0)}/100")
                    st.write(f"- Classification: {ip_result.get('classification', 'Unknown')}")
                    
                    geo = ip_result.get('geolocation', {})
                    if geo:
                        st.write(f"- Country: {geo.get('country', 'Unknown')}")
                        st.write(f"- City: {geo.get('city', 'Unknown')}")
                        st.write(f"- ISP: {geo.get('isp', 'Unknown')}")
                
                with col2:
                    st.write("**Risk Factors:**")
                    risk_factors = ip_result.get('risk_factors', [])
                    if risk_factors:
                        for factor in risk_factors:
                            st.write(f"- {factor}")
                    else:
                        st.write("- No specific risk factors identified")
                    
                    # Open ports
                    open_ports = ip_result.get('open_ports', {})
                    if open_ports.get('suspicious_open_ports'):
                        st.write("**Suspicious Open Ports:**")
                        for port in open_ports['suspicious_open_ports']:
                            st.write(f"- Port {port}")

def create_network_timeline_chart(connections):
    """Create network activity timeline"""
    if not connections:
        return None
    
    try:
        df = pd.DataFrame(connections)
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df['hour'] = df['timestamp'].dt.floor('H')
            
            # Group by hour and count connections
            hourly_counts = df.groupby('hour').size().reset_index(name='connection_count')
            
            fig = px.line(
                hourly_counts,
                x='hour',
                y='connection_count',
                title='Network Activity Timeline',
                labels={'hour': 'Time', 'connection_count': 'Connections per Hour'}
            )
            
            return fig
    except Exception as e:
        st.error(f"Failed to create timeline chart: {str(e)}")
        return None

def main():
    """Main network analysis interface"""
    st.title("🌐 Network Traffic Analysis & Monitoring")
    st.markdown("Analyze network connections, detect anomalies, and assess IP reputation")
    
    # Initialize analyzers
    analyzers = init_analyzers()
    if not analyzers:
        st.stop()
    
    # Analysis options
    st.subheader("📊 Analysis Options")
    
    tab1, tab2, tab3 = st.tabs(["📝 Log Analysis", "🔄 Live Analysis", "📁 Upload Logs"])
    
    with tab1:
        st.info("📝 **Sample Network Data Analysis**")
        st.write("Analyze sample network data to demonstrate anomaly detection capabilities")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            num_connections = st.slider("Number of Connections", 50, 500, 100)
        with col2:
            anomaly_rate = st.slider("Anomaly Rate (%)", 0, 50, 10)
        with col3:
            if st.button("🔍 Generate & Analyze Sample Data", type="primary", use_container_width=True):
                st.session_state.analyze_sample_network = True
        
        if st.session_state.get('analyze_sample_network', False):
            analyze_sample_network_data(analyzers, num_connections, anomaly_rate)
    
    with tab2:
        st.info("🔄 **Live Network Monitoring**")
        st.write("Monitor live network connections (requires appropriate permissions and is a feature in development)")
        
        if st.button("🔴 Start Live Monitoring", type="primary"):
            with st.spinner("Collecting network information..."):
                network_info = analyzers['ip_analyzer'].get_local_network_info()
                
                if 'error' in network_info:
                    st.error(f"Failed to get network info: {network_info['error']}")
                else:
                    display_local_network_info(network_info)
    
    with tab3:
        st.info("📁 **Upload Network Logs**")
        st.write("Upload network log files for analysis")
        
        uploaded_file = st.file_uploader(
            "Choose a network log file",
            type=['log', 'txt', 'csv', 'json'],
            help="Supported formats: .log, .txt, .csv, .json"
        )
        
        if uploaded_file is not None:
            if st.button("🔍 Analyze Uploaded Logs", type="primary"):
                analyze_uploaded_logs(analyzers, uploaded_file)

def analyze_sample_network_data(analyzers, num_connections, anomaly_rate):
    """Analyze sample network data"""
    try:
        # Progress tracking
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Generate sample data
        status_text.text("🔄 Generating sample network data...")
        progress_bar.progress(20)
        
        connections = analyzers['network_analyzer'].create_sample_network_data(num_connections)
        
        # Parse and enrich data
        status_text.text("🔍 Analyzing network connections...")
        progress_bar.progress(40)
        
        parsed_connections = analyzers['network_analyzer'].parse_network_log(connections)
        
        # Detect anomalies
        status_text.text("🚨 Detecting network anomalies...")
        progress_bar.progress(60)
        
        anomalies = analyzers['network_analyzer'].detect_anomalies(parsed_connections)
        
        # Generate network summary
        status_text.text("📊 Generating network summary...")
        progress_bar.progress(80)
        
        network_summary = analyzers['network_analyzer'].generate_network_summary(parsed_connections)
        
        # IP analysis for high-risk connections
        status_text.text("🌍 Analyzing IP addresses...")
        progress_bar.progress(90)
        
        high_risk_ips = [conn['remote_ip'] for conn in parsed_connections if conn.get('risk_score', 0) >= 70]
        unique_high_risk_ips = list(set(high_risk_ips))[:10]  # Limit to 10 IPs
        
        ip_results = None
        if unique_high_risk_ips:
            ip_results = analyzers['ip_analyzer'].batch_analyze_ips(unique_high_risk_ips)
        
        # Generate report
        report = analyzers['report_generator'].generate_network_analysis_report(parsed_connections, anomalies)
        
        progress_bar.progress(100)
        status_text.text("✅ Analysis complete!")
        
        # Clear progress indicators
        progress_bar.empty()
        status_text.empty()
        
        display_network_analysis_results(network_summary, anomalies, ip_results, report, parsed_connections, analyzers)
        
        # Update session state
        st.session_state.analyze_sample_network = False
        
    except Exception as e:
        st.error(f"Network analysis failed: {str(e)}")
        st.session_state.analyze_sample_network = False

def analyze_uploaded_logs(analyzers, uploaded_file):
    """Analyze uploaded network logs"""
    try:
        # Read file content
        file_content = uploaded_file.read().decode('utf-8')
        
        with st.spinner("Analyzing uploaded network logs..."):
            # Parse log data
            connections = analyzers['network_analyzer'].parse_network_log(file_content)
            
            if not connections:
                st.warning("No valid network connections found in the uploaded file")
                return
            
            # Analyze connections
            anomalies = analyzers['network_analyzer'].detect_anomalies(connections)
            network_summary = analyzers['network_analyzer'].generate_network_summary(connections)
            
            # Generate report
            report = analyzers['report_generator'].generate_network_analysis_report(connections, anomalies)
            
            display_network_analysis_results(network_summary, anomalies, None, report, connections, analyzers)
            
    except Exception as e:
        st.error(f"Failed to analyze uploaded logs: {str(e)}")


def display_network_analysis_results(network_summary, anomalies, ip_results, report, connections, analyzers):
    """Display comprehensive network analysis results"""
    st.success("🎯 Network Analysis Complete!")

    # Overview metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Connections", network_summary.get('total_connections', 0))
    with col2:
        st.metric("Unique IPs", network_summary.get('unique_remote_ips', 0))
    with col3:
        st.metric("Anomalies Detected", anomalies.get('anomaly_count', 0))
    with col4:
        risk_level = report.get('risk_assessment', {}).get('risk_level', 'UNKNOWN')
        risk_color = {'LOW': '🟢', 'MEDIUM': '🟡', 'HIGH': '🟠', 'CRITICAL': '🔴'}.get(risk_level, '⚪')
        st.metric("Risk Level", f"{risk_color} {risk_level}")

    st.divider()

    # Detailed analysis in tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📊 Overview",
        "🚨 Anomalies",
        "🌍 IP Analysis",
        "⏱️ Timeline",
        "📋 Report"
    ])

    with tab1:
        st.subheader("📊 Network Overview")
        charts = create_network_overview_charts(network_summary)
        if charts:
            chart_col1, chart_col2 = st.columns(2)
            with chart_col1:
                if 'protocol' in charts:
                    st.plotly_chart(charts['protocol'], use_container_width=True)
                if 'risk' in charts:
                    st.plotly_chart(charts['risk'], use_container_width=True)
            with chart_col2:
                if 'top_ips' in charts:
                    st.plotly_chart(charts['top_ips'], use_container_width=True)

        # Data transfer summary
        if 'data_transfer' in network_summary:
            data_transfer = network_summary['data_transfer']
            st.subheader("📈 Data Transfer Summary")
            transfer_col1, transfer_col2, transfer_col3 = st.columns(3)
            with transfer_col1:
                st.metric("Total Sent", f"{data_transfer.get('total_bytes_sent', 0):,} bytes")
            with transfer_col2:
                st.metric("Total Received", f"{data_transfer.get('total_bytes_recv', 0):,} bytes")
            with transfer_col3:
                total_transfer = data_transfer.get('total_bytes_sent', 0) + data_transfer.get('total_bytes_recv', 0)
                st.metric("Total Transfer", f"{total_transfer:,} bytes")

    with tab2:
        st.subheader("🚨 Network Anomalies")
        display_anomaly_details(anomalies)

    with tab3:
        if ip_results:
            display_ip_analysis_results(ip_results)
        else:
            st.info("No high-risk IP addresses detected for detailed analysis")

    with tab4:
        st.subheader("⏱️ Network Activity Timeline")
        timeline_chart = create_network_timeline_chart(connections)
        if timeline_chart:
            st.plotly_chart(timeline_chart, use_container_width=True)
        else:
            st.info("Timeline data not available")

    with tab5:
        st.subheader("📋 Analysis Report")
        summary = report.get('summary', {})
        st.write("**Report Summary:**")
        for key, value in summary.items():
            if key != 'primary_concerns':
                st.write(f"- **{key.replace('_', ' ').title()}:** {value}")

        if 'primary_concerns' in summary and summary['primary_concerns']:
            st.write("**Primary Concerns:**")
            for concern in summary['primary_concerns']:
                st.write(f"- {concern}")

        # Download report using analyzers
        report_json = analyzers['report_generator'].export_report_to_json(report)
        st.download_button(
            label="📥 Download Analysis Report",
            data=report_json,
            file_name=f"network_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )

        with st.expander("🔍 View Full Report", expanded=False):
            st.json(report)


def display_local_network_info(network_info):
    """Display local network interface information"""
    st.subheader("🖥️ Local Network Information")
    
    # Network interfaces
    if 'interfaces' in network_info:
        st.write("**Network Interfaces:**")
        
        for interface in network_info['interfaces']:
            with st.expander(f"🔌 Interface: {interface['interface']}", expanded=False):
                addresses = interface.get('addresses', [])
                if addresses:
                    for addr in addresses:
                        st.write(f"- **{addr['type']}:** {addr['address']}")
                        if 'netmask' in addr:
                            st.write(f"  - Netmask: {addr['netmask']}")
                        if 'broadcast' in addr:
                            st.write(f"  - Broadcast: {addr['broadcast']}")
    
    # Active connections
    if 'connections' in network_info:
        connections = network_info['connections']
        if connections:
            st.write(f"**Active Network Connections:** ({len(connections)} shown)")
            
            conn_df = pd.DataFrame(connections)
            st.dataframe(conn_df, use_container_width=True)

if __name__ == "__main__":
    main()
