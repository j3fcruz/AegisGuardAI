import streamlit as st
import pandas as pd
import plotly.graph_objects as go

# ------------------- VISUAL HELPERS -------------------
def create_reputation_gauge(reputation_info):
    """Create a Plotly gauge chart for reputation score"""
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
            'axis': {'range': [0, 100]},
            'bar': {'color': color_map.get(level, '#6c757d')},
            'steps': [
                {'range': [0, 25], 'color': "lightgreen"},
                {'range': [25, 50], 'color': "yellow"},
                {'range': [50, 75], 'color': "orange"},
                {'range': [75, 100], 'color': "red"}
            ]
        }
    ))
    fig.update_layout(height=300, margin=dict(l=0, r=0, t=50, b=0))
    return fig

def create_detection_stats_chart(detection_stats):
    """Create a bar chart for detection engine results"""
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

# ------------------- DISPLAY FUNCTIONS -------------------
def display_file_hash_results(result):
    """Display the results of a file hash lookup"""
    if 'error' in result:
        st.error(f"Lookup failed: {result['error']}")
        return

    if not result.get('found', True):
        st.info("🔍 Hash not found in threat intelligence database")
        return

    reputation = result.get('reputation', {})
    level = reputation.get('level', 'UNKNOWN')
    col1, col2 = st.columns([1, 2])

    with col1:
        st.plotly_chart(create_reputation_gauge(reputation), use_container_width=True)

    with col2:
        st.subheader("🎯 Key Findings")
        detection_ratio = result.get('detection_ratio', 'N/A')
        harmful_detections = reputation.get('harmful_detections', 0)
        total_scanned = reputation.get('total_scanned', 0)

        metric_col1, metric_col2, metric_col3 = st.columns(3)
        with metric_col1: st.metric("Detection Ratio", detection_ratio)
        with metric_col2: st.metric("Harmful Detections", harmful_detections)
        with metric_col3: st.metric("Total Engines", total_scanned)

        if level in ['MALICIOUS', 'SUSPICIOUS']:
            st.error(f"🚨 Threat Detected: {level}")
        elif level == 'QUESTIONABLE':
            st.warning("⚠️ Some suspicious characteristics detected")
        else:
            st.success("✅ No threats detected")

    if 'detection_stats' in result:
        chart = create_detection_stats_chart(result['detection_stats'])
        if chart: st.plotly_chart(chart, use_container_width=True)

    if 'file_info' in result:
        st.subheader("📄 File Information")
        info_col1, info_col2 = st.columns(2)
        file_info = result['file_info']

        with info_col1:
            st.write("**Basic Properties:**")
            if file_info.get('size'): st.write(f"- Size: {file_info['size']:,} bytes")
            if file_info.get('type_description'): st.write(f"- Type: {file_info['type_description']}")
            if file_info.get('magic'): st.write(f"- Magic: {file_info['magic']}")

        with info_col2:
            st.write("**Hash Values:**")
            for hash_type in ['md5', 'sha1', 'sha256']:
                if file_info.get(hash_type): st.code(f"{hash_type.upper()}: {file_info[hash_type]}")

    if 'scan_results' in result:
        st.subheader("🔬 Detailed Scan Results")
        scan_results = result['scan_results']

        malicious = {k: v for k, v in scan_results.items() if v.get('category') == 'malicious'}
        suspicious = {k: v for k, v in scan_results.items() if v.get('category') == 'suspicious'}

        if malicious:
            with st.expander(f"🔴 Malicious Detections ({len(malicious)})", expanded=True):
                for engine, details in malicious.items():
                    col1, col2, col3 = st.columns([2, 2, 1])
                    with col1: st.write(f"**{engine}**")
                    with col2: st.write(f"Result: {details.get('result', 'N/A')}")
                    with col3: st.write(f"v{details.get('version', 'N/A')}")

        if suspicious:
            with st.expander(f"🟠 Suspicious Detections ({len(suspicious)})", expanded=False):
                for engine, details in suspicious.items():
                    col1, col2, col3 = st.columns([2, 2, 1])
                    with col1: st.write(f"**{engine}**")
                    with col2: st.write(f"Result: {details.get('result', 'N/A')}")
                    with col3: st.write(f"v{details.get('version', 'N/A')}")

def display_ip_results(result, ip_analysis=None):
    """Display IP address lookup results"""
    if 'error' in result:
        st.error(f"Lookup failed: {result['error']}")
        return

    if not result.get('found', True):
        st.info("🔍 IP not found in threat intelligence database")
        return

    reputation = result.get('reputation', {})
    level = reputation.get('level', 'UNKNOWN')
    col1, col2 = st.columns([1, 2])

    with col1:
        st.plotly_chart(create_reputation_gauge(reputation), use_container_width=True)

    with col2:
        st.subheader("🌐 IP Information")
        info_col1, info_col2 = st.columns(2)
        with info_col1:
            st.write(f"- Country: {result.get('country', 'Unknown')}")
            if result.get('as_owner'): st.write(f"- AS Owner: {result.get('as_owner')}")
            if result.get('asn'): st.write(f"- ASN: {result.get('asn')}")
        with info_col2:
            if result.get('network'): st.write(f"- Network: {result.get('network')}")
            if result.get('regional_internet_registry'): st.write(f"- RIR: {result.get('regional_internet_registry')}")
            st.metric("Detection Ratio", result.get('detection_ratio', 'N/A'))

        if ip_analysis:
            st.subheader("🔍 Detailed IP Analysis")
            st.write(f"- Classification: {ip_analysis.get('classification', 'Unknown')}")
            st.write(f"- Risk Score: {ip_analysis.get('risk_score', 0)}/100")
            if ip_analysis.get('is_private'): st.info("🏠 Private IP")
            elif ip_analysis.get('is_global'): st.info("🌍 Public IP")

            risk_factors = ip_analysis.get('risk_factors', [])
            if risk_factors:
                st.write("**Risk Factors:**")
                for rf in risk_factors: st.warning(f"- {rf}")
            else:
                st.success("- No risk factors detected")

            open_ports = ip_analysis.get('open_ports', {})
            if open_ports.get('open_ports'):
                st.write("**Open Ports:**")
                ports_df = pd.DataFrame([
                    {'Port': p, 'Service': s}
                    for p, s in zip(open_ports['open_ports'], open_ports.get('common_services', []))
                ])
                st.dataframe(ports_df, use_container_width=True)
                if open_ports.get('suspicious_open_ports'):
                    st.error(f"⚠️ Suspicious ports detected: {open_ports['suspicious_open_ports']}")

def display_domain_results(result):
    """Display domain lookup results"""
    if 'error' in result:
        st.error(f"Lookup failed: {result['error']}")
        return

    if not result.get('found', True):
        st.info("🔍 Domain not found in threat intelligence database")
        return

    reputation = result.get('reputation', {})
    level = reputation.get('level', 'UNKNOWN')
    col1, col2 = st.columns([1, 2])

    with col1:
        st.plotly_chart(create_reputation_gauge(reputation), use_container_width=True)

    with col2:
        st.subheader("🌐 Domain Information")
        domain_col1, domain_col2 = st.columns(2)
        with domain_col1:
            if result.get('creation_date'): st.write(f"- Created: {result.get('creation_date')}")
            if result.get('registrar'): st.write(f"- Registrar: {result.get('registrar')}")
            if result.get('last_update_date'): st.write(f"- Updated: {result.get('last_update_date')}")
        with domain_col2:
            st.metric("Detection Ratio", result.get('detection_ratio', 'N/A'))
            categories = result.get('categories', {})
            if categories:
                st.write("**Categories:**")
                for src, cat_list in categories.items():
                    st.write(f"- {src}: {', '.join(cat_list) if isinstance(cat_list, list) else cat_list}")

        if 'dns_records' in result:
            st.subheader("🔗 DNS Records")
            record_types = {}
            for record in result['dns_records']:
                record_types.setdefault(record.get('type', 'Unknown'), []).append(record)
            for rtype, records in record_types.items():
                with st.expander(f"{rtype} Records ({len(records)})"):
                    for rec in records:
                        st.write(f"- Value: {rec.get('value', 'N/A')}")
                        if rec.get('ttl'): st.write(f"  - TTL: {rec['ttl']}")
