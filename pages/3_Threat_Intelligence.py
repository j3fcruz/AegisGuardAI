# pages/3_Threat_Intelligence.py
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import sys
import os
import re
import ipaddress

# Add the project root to the path to import utilities
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.threat_intelligence import ThreatIntelligence
from utils.ip_analyzer import IPAnalyzer
from utils.report_generator import ReportGenerator

# Page configuration
st.set_page_config(
    page_title="Threat Intelligence - CyberSecure Dashboard",
    page_icon="🔍",
    layout="wide"
)


# Initialize analyzers
@st.cache_resource
def init_analyzers():
    """Initialize analyzer classes with caching"""
    try:
        return {
            'threat_intel': ThreatIntelligence(),
            'ip_analyzer': IPAnalyzer(),
            'report_generator': ReportGenerator()
        }
    except Exception as e:
        st.error(f"Failed to initialize analyzers: {str(e)}")
        return None


def validate_hash(hash_value, hash_type):
    """Validate hash format"""
    hash_lengths = {'md5': 32, 'sha1': 40, 'sha256': 64}

    if hash_type not in hash_lengths:
        return False, "Invalid hash type"

    if len(hash_value) != hash_lengths[hash_type]:
        return False, f"{hash_type.upper()} hash must be {hash_lengths[hash_type]} characters long"

    if not re.match(r'^[a-fA-F0-9]+$', hash_value):
        return False, "Hash must contain only hexadecimal characters"

    return True, ""


def validate_ip(ip_address):
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip_address)
        return True, ""
    except ipaddress.AddressValueError:
        return False, "Invalid IP address format"


def validate_domain(domain):
    """Validate domain format"""
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'

    if not re.match(domain_pattern, domain):
        return False, "Invalid domain format"

    if len(domain) > 253:
        return False, "Domain name too long"

    return True, ""


def create_reputation_gauge(reputation_info):
    """Create reputation gauge visualization"""
    score = reputation_info.get('score', 0)
    level = reputation_info.get('level', 'UNKNOWN')

    color_map = {
        'CLEAN': '#28a745',
        'QUESTIONABLE': '#ffc107',
        'SUSPICIOUS': '#fd7e14',
        'MALICIOUS': '#dc3545',
        'UNKNOWN': '#6c757d'
    }

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': f"Reputation: {level}"},
        gauge={
            'axis': {'range': [None, 100]},
            'bar': {'color': color_map.get(level, '#6c757d')},
            'steps': [
                {'range': [0, 25], 'color': "lightgreen"},
                {'range': [25, 50], 'color': "yellow"},
                {'range': [50, 75], 'color': "orange"},
                {'range': [75, 100], 'color': "red"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))

    fig.update_layout(height=300, margin=dict(l=0, r=0, t=50, b=0))
    return fig


def create_detection_stats_chart(detection_stats):
    """Create detection statistics chart"""
    if not detection_stats:
        return None

    categories = list(detection_stats.keys())
    values = list(detection_stats.values())

    colors = {
        'malicious': '#dc3545',
        'suspicious': '#fd7e14',
        'undetected': '#6c757d',
        'harmless': '#28a745',
        'timeout': '#17a2b8',
        'confirmed_timeout': '#17a2b8',
        'failure': '#6f42c1',
        'type_unsupported': '#6f42c1'
    }

    fig = go.Figure(data=[go.Bar(
        x=categories,
        y=values,
        marker_color=[colors.get(cat, '#6c757d') for cat in categories]
    )])

    fig.update_layout(
        title='Detection Results by Security Engines',
        xaxis_title='Detection Category',
        yaxis_title='Number of Engines',
        height=400
    )

    return fig


def display_file_hash_results(result):
    """Display file hash lookup results"""
    if 'error' in result:
        st.error(f"Lookup failed: {result['error']}")
        return

    if not result.get('found'):
        st.info("🔍 Hash not found in threat intelligence database")
        st.write("This could indicate:")
        st.write("- The file is new or rare")
        st.write("- The file is clean and not widely scanned")
        st.write("- The hash is not in the current database")
        return

    # Reputation overview
    reputation = result.get('reputation', {})
    level = reputation.get('level', 'UNKNOWN')

    col1, col2 = st.columns([1, 2])

    with col1:
        # Reputation gauge
        fig_gauge = create_reputation_gauge(reputation)
        st.plotly_chart(fig_gauge, use_container_width=True)

    with col2:
        # Key metrics
        st.subheader("🎯 Key Findings")

        metric_col1, metric_col2, metric_col3 = st.columns(3)

        with metric_col1:
            detection_ratio = result.get('detection_ratio', 'N/A')
            st.metric("Detection Ratio", detection_ratio)

        with metric_col2:
            harmful_detections = reputation.get('harmful_detections', 0)
            st.metric("Harmful Detections", harmful_detections)

        with metric_col3:
            total_scanned = reputation.get('total_scanned', 0)
            st.metric("Total Engines", total_scanned)

        # Risk assessment
        if level in ['MALICIOUS', 'SUSPICIOUS']:
            st.error(f"🚨 **THREAT DETECTED** - This file is flagged as {level}")
            if level == 'MALICIOUS':
                st.write("**Immediate Actions Required:**")
                st.write("- Do NOT execute this file")
                st.write("- Quarantine the file immediately")
                st.write("- Scan the system for infections")
                st.write("- Report to security team")
        elif level == 'QUESTIONABLE':
            st.warning("⚠️ **CAUTION** - This file shows some suspicious characteristics")
        else:
            st.success("✅ **CLEAN** - No threats detected by security engines")

    # Detection statistics
    if 'detection_stats' in result:
        st.subheader("📊 Detection Statistics")

        detection_chart = create_detection_stats_chart(result['detection_stats'])
        if detection_chart:
            st.plotly_chart(detection_chart, use_container_width=True)

    # File information
    if 'file_info' in result:
        file_info = result['file_info']
        st.subheader("📄 File Information")

        info_col1, info_col2 = st.columns(2)

        with info_col1:
            st.write("**Basic Properties:**")
            if file_info.get('size'):
                st.write(f"- **Size:** {file_info['size']:,} bytes")
            if file_info.get('type_description'):
                st.write(f"- **Type:** {file_info['type_description']}")
            if file_info.get('magic'):
                st.write(f"- **Magic:** {file_info['magic']}")

        with info_col2:
            st.write("**Hash Values:**")
            for hash_type in ['md5', 'sha1', 'sha256']:
                hash_value = file_info.get(hash_type)
                if hash_value:
                    st.code(f"{hash_type.upper()}: {hash_value}")

    # Scan results details
    if 'scan_results' in result and result['scan_results']:
        st.subheader("🔬 Detailed Scan Results")

        scan_results = result['scan_results']

        # Filter results by category
        malicious_results = {k: v for k, v in scan_results.items() if v.get('category') == 'malicious'}
        suspicious_results = {k: v for k, v in scan_results.items() if v.get('category') == 'suspicious'}

        if malicious_results:
            with st.expander(f"🔴 Malicious Detections ({len(malicious_results)})", expanded=True):
                for engine, details in malicious_results.items():
                    col1, col2, col3 = st.columns([2, 2, 1])
                    with col1:
                        st.write(f"**{engine}**")
                    with col2:
                        st.write(f"Result: {details.get('result', 'N/A')}")
                    with col3:
                        st.write(f"v{details.get('version', 'N/A')}")

        if suspicious_results:
            with st.expander(f"🟠 Suspicious Detections ({len(suspicious_results)})", expanded=False):
                for engine, details in suspicious_results.items():
                    col1, col2, col3 = st.columns([2, 2, 1])
                    with col1:
                        st.write(f"**{engine}**")
                    with col2:
                        st.write(f"Result: {details.get('result', 'N/A')}")
                    with col3:
                        st.write(f"v{details.get('version', 'N/A')}")


def display_ip_results(result, ip_analysis=None):
    """Display IP address lookup results"""
    if 'error' in result:
        st.error(f"Lookup failed: {result['error']}")
        return

    if not result.get('found'):
        st.info("🔍 IP address not found in threat intelligence database")
        return

    # Reputation and basic info
    reputation = result.get('reputation', {})
    level = reputation.get('level', 'UNKNOWN')

    col1, col2 = st.columns([1, 2])

    with col1:
        # Reputation gauge
        fig_gauge = create_reputation_gauge(reputation)
        st.plotly_chart(fig_gauge, use_container_width=True)

    with col2:
        st.subheader("🌐 IP Information")

        info_col1, info_col2 = st.columns(2)

        with info_col1:
            st.write("**Geographic Information:**")
            st.write(f"- **Country:** {result.get('country', 'Unknown')}")
            if result.get('as_owner'):
                st.write(f"- **AS Owner:** {result.get('as_owner')}")
            if result.get('asn'):
                st.write(f"- **ASN:** {result.get('asn')}")

        with info_col2:
            st.write("**Network Information:**")
            if result.get('network'):
                st.write(f"- **Network:** {result.get('network')}")
            if result.get('regional_internet_registry'):
                st.write(f"- **RIR:** {result.get('regional_internet_registry')}")

            detection_ratio = result.get('detection_ratio', 'N/A')
            st.metric("Detection Ratio", detection_ratio)

    # Display IP analysis if available
    if ip_analysis and not ip_analysis.get('error'):
        st.subheader("🔍 Detailed IP Analysis")

        analysis_col1, analysis_col2 = st.columns(2)

        with analysis_col1:
            st.write("**Classification:**")
            st.write(f"- **Type:** {ip_analysis.get('classification', 'Unknown')}")
            st.write(f"- **Risk Score:** {ip_analysis.get('risk_score', 0)}/100")

            if ip_analysis.get('is_private'):
                st.info("🏠 This is a private IP address")
            elif ip_analysis.get('is_global'):
                st.info("🌍 This is a public IP address")

        with analysis_col2:
            # Risk factors
            risk_factors = ip_analysis.get('risk_factors', [])
            if risk_factors:
                st.write("**Risk Factors:**")
                for factor in risk_factors:
                    st.warning(f"- {factor}")
            else:
                st.success("- No specific risk factors identified")

        # Open ports information
        open_ports = ip_analysis.get('open_ports', {})
        if open_ports.get('open_ports'):
            st.write("**Open Ports:**")
            ports_df = pd.DataFrame([
                {'Port': port, 'Service': service}
                for port, service in zip(
                    open_ports['open_ports'],
                    open_ports.get('common_services', ['Unknown'] * len(open_ports['open_ports']))
                )
            ])
            st.dataframe(ports_df, use_container_width=True)

            if open_ports.get('suspicious_open_ports'):
                st.error(f"⚠️ Suspicious ports detected: {open_ports['suspicious_open_ports']}")


def display_domain_results(result):
    """Display domain lookup results"""
    if 'error' in result:
        st.error(f"Lookup failed: {result['error']}")
        return

    if not result.get('found'):
        st.info("🔍 Domain not found in threat intelligence database")
        return

    # Reputation overview
    reputation = result.get('reputation', {})
    level = reputation.get('level', 'UNKNOWN')

    col1, col2 = st.columns([1, 2])

    with col1:
        # Reputation gauge
        fig_gauge = create_reputation_gauge(reputation)
        st.plotly_chart(fig_gauge, use_container_width=True)

    with col2:
        st.subheader("🌐 Domain Information")

        domain_col1, domain_col2 = st.columns(2)

        with domain_col1:
            st.write("**Registration Info:**")
            if result.get('creation_date'):
                st.write(f"- **Created:** {result.get('creation_date')}")
            if result.get('registrar'):
                st.write(f"- **Registrar:** {result.get('registrar')}")
            if result.get('last_update_date'):
                st.write(f"- **Updated:** {result.get('last_update_date')}")

        with domain_col2:
            st.write("**Threat Intelligence:**")
            detection_ratio = result.get('detection_ratio', 'N/A')
            st.metric("Detection Ratio", detection_ratio)

            # Categories
            categories = result.get('categories', {})
            if categories:
                st.write("**Categories:**")
                for source, category_list in categories.items():
                    if isinstance(category_list, list):
                        st.write(f"- {source}: {', '.join(category_list)}")

    # DNS records
    if 'dns_records' in result and result['dns_records']:
        st.subheader("🔗 DNS Records")

        dns_records = result['dns_records']
        if dns_records:
            # Group records by type
            record_types = {}
            for record in dns_records:
                record_type = record.get('type', 'Unknown')
                if record_type not in record_types:
                    record_types[record_type] = []
                record_types[record_type].append(record)

            for record_type, records in record_types.items():
                with st.expander(f"{record_type} Records ({len(records)})", expanded=False):
                    for record in records:
                        st.write(f"- **Value:** {record.get('value', 'N/A')}")
                        if record.get('ttl'):
                            st.write(f"  - TTL: {record['ttl']}")


def main():
    """Main threat intelligence interface"""
    st.title("🔍 Threat Intelligence & IOC Analysis")
    st.markdown("Lookup file hashes, IP addresses, and domains against threat intelligence databases")

    # Initialize analyzers
    analyzers = init_analyzers()
    if not analyzers:
        st.stop()

    # API status check
    with st.expander("⚙️ API Configuration Status", expanded=False):
        api_status = analyzers['threat_intel'].get_api_status()

        if api_status.get('apis', {}).get('virustotal', {}).get('configured'):
            st.success("✅ VirusTotal API configured")

            rate_limit = api_status['apis']['virustotal'].get('rate_limit', {})
            st.write(f"**Rate Limit:** {rate_limit.get('requests_per_minute', 'Unknown')} requests/minute")
            st.write(f"**Cache Entries:** {api_status.get('cache_stats', {}).get('total_entries', 0)}")
        else:
            st.warning("⚠️ VirusTotal API not configured - using cached/demo data")
            st.info("Set the VIRUSTOTAL_API_KEY environment variable to enable live lookups")

    st.divider()

    # Lookup options
    tab1, tab2, tab3, tab4 = st.tabs(["🔗 Single Lookup", "📋 Batch Lookup", "📊 Analysis Report", "🔄 Batch Upload"])

    with tab1:
        st.subheader("🔍 Single Indicator Lookup")

        # Indicator type selection
        indicator_type = st.selectbox(
            "Select indicator type:",
            ["File Hash", "IP Address", "Domain"],
            key="single_indicator_type"
        )

        if indicator_type == "File Hash":
            col1, col2 = st.columns([2, 1])

            with col1:
                hash_value = st.text_input(
                    "Enter file hash:",
                    placeholder="e.g., d41d8cd98f00b204e9800998ecf8427e",
                    key="single_hash"
                )

            with col2:
                hash_type = st.selectbox("Hash type:", ["md5", "sha1", "sha256"], key="single_hash_type")

            if st.button("🔍 Lookup Hash", type="primary"):
                if hash_value:
                    is_valid, error_msg = validate_hash(hash_value, hash_type)
                    if is_valid:
                        with st.spinner(f"Looking up {hash_type.upper()} hash..."):
                            result = analyzers['threat_intel'].lookup_file_hash(hash_value, hash_type)
                            st.subheader(f"📄 Hash Lookup Results: {hash_value}")
                            display_file_hash_results(result)
                    else:
                        st.error(f"Invalid hash: {error_msg}")
                else:
                    st.warning("Please enter a hash value")

        elif indicator_type == "IP Address":
            ip_address = st.text_input(
                "Enter IP address:",
                placeholder="e.g., 8.8.8.8",
                key="single_ip"
            )

            if st.button("🔍 Lookup IP", type="primary"):
                if ip_address:
                    is_valid, error_msg = validate_ip(ip_address)
                    if is_valid:
                        with st.spinner("Looking up IP address..."):
                            # Threat intelligence lookup
                            ti_result = analyzers['threat_intel'].lookup_ip_address(ip_address)

                            # Detailed IP analysis
                            ip_analysis = analyzers['ip_analyzer'].analyze_ip(ip_address)

                            st.subheader(f"🌐 IP Address Results: {ip_address}")
                            display_ip_results(ti_result, ip_analysis)
                    else:
                        st.error(f"Invalid IP address: {error_msg}")
                else:
                    st.warning("Please enter an IP address")

        elif indicator_type == "Domain":
            domain = st.text_input(
                "Enter domain:",
                placeholder="e.g., example.com",
                key="single_domain"
            )

            if st.button("🔍 Lookup Domain", type="primary"):
                if domain:
                    is_valid, error_msg = validate_domain(domain)
                    if is_valid:
                        with st.spinner("Looking up domain..."):
                            result = analyzers['threat_intel'].lookup_domain(domain)
                            st.subheader(f"🌐 Domain Results: {domain}")
                            display_domain_results(result)
                    else:
                        st.error(f"Invalid domain: {error_msg}")
                else:
                    st.warning("Please enter a domain name")

    with tab2:
        st.subheader("📋 Batch Indicator Lookup")
        st.write("Enter multiple indicators (one per line) for batch analysis")

        batch_input = st.text_area(
            "Enter indicators:",
            placeholder="8.8.8.8\nexample.com\nd41d8cd98f00b204e9800998ecf8427e",
            height=150,
            key="batch_input"
        )

        if st.button("🔍 Batch Lookup", type="primary"):
            if batch_input.strip():
                indicators = []
                lines = batch_input.strip().split('\n')

                for line in lines:
                    line = line.strip()
                    if not line:
                        continue

                    # Auto-detect indicator type
                    if re.match(r'^[a-fA-F0-9]{32}$', line):
                        indicators.append({'type': 'hash', 'value': line, 'hash_type': 'md5'})
                    elif re.match(r'^[a-fA-F0-9]{40}$', line):
                        indicators.append({'type': 'hash', 'value': line, 'hash_type': 'sha1'})
                    elif re.match(r'^[a-fA-F0-9]{64}$', line):
                        indicators.append({'type': 'hash', 'value': line, 'hash_type': 'sha256'})
                    elif validate_ip(line)[0]:
                        indicators.append({'type': 'ip', 'value': line})
                    elif validate_domain(line)[0]:
                        indicators.append({'type': 'domain', 'value': line})
                    else:
                        st.warning(f"Could not determine type for indicator: {line}")

                if indicators:
                    with st.spinner(f"Processing {len(indicators)} indicators..."):
                        results = analyzers['threat_intel'].batch_lookup(indicators)

                        st.success(f"✅ Batch lookup complete! Processed {len(indicators)} indicators")

                        # Display summary
                        summary = results.get('summary', {})

                        summary_col1, summary_col2, summary_col3, summary_col4 = st.columns(4)

                        with summary_col1:
                            st.metric("Total Processed", summary.get('successful', 0))
                        with summary_col2:
                            st.metric("Malicious", summary.get('malicious', 0))
                        with summary_col3:
                            st.metric("Suspicious", summary.get('suspicious', 0))
                        with summary_col4:
                            st.metric("Clean", summary.get('clean', 0))

                        # Display individual results
                        st.subheader("📊 Individual Results")

                        for item in results.get('results', []):
                            indicator = item.get('indicator', {})
                            result = item.get('result', {})

                            indicator_value = indicator.get('value', 'Unknown')
                            indicator_type = indicator.get('type', 'Unknown')

                            with st.expander(f"{indicator_type.upper()}: {indicator_value}", expanded=False):
                                if 'error' in result:
                                    st.error(f"Error: {result['error']}")
                                elif result.get('found'):
                                    reputation = result.get('reputation', {})
                                    level = reputation.get('level', 'UNKNOWN')
                                    level_color = {
                                        'MALICIOUS': '🔴',
                                        'SUSPICIOUS': '🟠',
                                        'QUESTIONABLE': '🟡',
                                        'CLEAN': '🟢',
                                        'UNKNOWN': '⚪'
                                    }.get(level, '⚪')

                                    st.write(f"**Reputation:** {level_color} {level}")
                                    st.write(f"**Detection Ratio:** {result.get('detection_ratio', 'N/A')}")
                                    st.write(f"**Source:** {result.get('source', 'Unknown')}")
                                else:
                                    st.info("Not found in threat intelligence database")
                else:
                    st.warning("No valid indicators found")
            else:
                st.warning("Please enter indicators to lookup")

    with tab3:
        st.subheader("📊 Threat Intelligence Analysis Report")
        st.write("Generate comprehensive reports from threat intelligence lookups")

        if 'batch_results' in st.session_state:
            st.info("Generate report from previous batch lookup results")

            if st.button("📊 Generate Report"):
                batch_results = st.session_state.batch_results

                # Convert batch results to threat intelligence report format
                threat_lookups = batch_results.get('results', [])

                with st.spinner("Generating threat intelligence report..."):
                    report = analyzers['report_generator'].generate_threat_intelligence_report(threat_lookups)

                    # Display report
                    st.success("📋 Threat Intelligence Report Generated")

                    # Report summary
                    summary = report.get('summary', {})

                    report_col1, report_col2, report_col3, report_col4 = st.columns(4)

                    with report_col1:
                        st.metric("Indicators Analyzed", summary.get('total_indicators', 0))
                    with report_col2:
                        st.metric("Malicious Found", summary.get('malicious_found', 0))
                    with report_col3:
                        st.metric("Suspicious Found", summary.get('suspicious_found', 0))
                    with report_col4:
                        st.metric("Clean Indicators", summary.get('clean_indicators', 0))

                    # Risk assessment
                    risk_assessment = report.get('risk_assessment', {})
                    risk_level = risk_assessment.get('risk_level', 'UNKNOWN')

                    st.subheader(f"🎯 Overall Risk Assessment: {risk_level}")

                    if risk_level in ['CRITICAL', 'HIGH']:
                        st.error("⚠️ High-risk indicators detected - immediate action recommended")
                    elif risk_level == 'MEDIUM':
                        st.warning("⚠️ Some suspicious indicators found - monitoring recommended")
                    else:
                        st.success("✅ No significant threats detected")

                    # Recommendations
                    if 'recommendations' in report:
                        st.subheader("💡 Recommendations")
                        for i, rec in enumerate(report['recommendations'], 1):
                            st.write(f"{i}. {rec}")

                    # Download report
                    report_json = analyzers['report_generator'].export_report_to_json(report)
                    st.download_button(
                        label="📥 Download Report",
                        data=report_json,
                        file_name=f"threat_intelligence_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
        else:
            st.info("No previous lookup results available. Perform a batch lookup first to generate reports.")

    with tab4:
        st.subheader("📁 Upload Indicators File")
        st.write("Upload a file containing indicators for bulk analysis")

        uploaded_file = st.file_uploader(
            "Choose indicators file:",
            type=['txt', 'csv'],
            help="Upload a text file with one indicator per line, or CSV with 'indicator' column"
        )

        if uploaded_file is not None:
            if st.button("🔍 Process File", type="primary"):
                try:
                    # Read file content
                    content = uploaded_file.read().decode('utf-8')

                    indicators = []

                    if uploaded_file.name.endswith('.csv'):
                        # Process CSV file
                        df = pd.read_csv(uploaded_file)
                        if 'indicator' in df.columns:
                            indicator_values = df['indicator'].dropna().tolist()
                        else:
                            st.error("CSV file must have an 'indicator' column")
                            st.stop()
                    else:
                        # Process text file
                        indicator_values = [line.strip() for line in content.split('\n') if line.strip()]

                    # Auto-detect indicator types
                    for value in indicator_values:
                        if re.match(r'^[a-fA-F0-9]{32}$', value):
                            indicators.append({'type': 'hash', 'value': value, 'hash_type': 'md5'})
                        elif re.match(r'^[a-fA-F0-9]{40}$', value):
                            indicators.append({'type': 'hash', 'value': value, 'hash_type': 'sha1'})
                        elif re.match(r'^[a-fA-F0-9]{64}$', value):
                            indicators.append({'type': 'hash', 'value': value, 'hash_type': 'sha256'})
                        elif validate_ip(value)[0]:
                            indicators.append({'type': 'ip', 'value': value})
                        elif validate_domain(value)[0]:
                            indicators.append({'type': 'domain', 'value': value})

                    if indicators:
                        st.info(f"Found {len(indicators)} valid indicators in file")

                        with st.spinner(f"Processing {len(indicators)} indicators from file..."):
                            results = analyzers['threat_intel'].batch_lookup(indicators)

                            # Store results for report generation
                            st.session_state.batch_results = results

                            st.success(f"✅ File processing complete!")

                            # Display summary
                            summary = results.get('summary', {})

                            file_col1, file_col2, file_col3, file_col4 = st.columns(4)

                            with file_col1:
                                st.metric("Total Processed", summary.get('successful', 0))
                            with file_col2:
                                st.metric("Malicious", summary.get('malicious', 0))
                            with file_col3:
                                st.metric("Suspicious", summary.get('suspicious', 0))
                            with file_col4:
                                st.metric("Clean", summary.get('clean', 0))
                    else:
                        st.warning("No valid indicators found in the uploaded file")

                except Exception as e:
                    st.error(f"Failed to process file: {str(e)}")


if __name__ == "__main__":
    main()
