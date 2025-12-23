# pages/1_File__Analysis.py
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import time
import sys
import os

# Add the project root to the path to import utilities
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.ui_helpers import init_analyzers
from utils.report_generator import ReportGenerator

# Page configuration
st.set_page_config(
    page_title="File Analysis - CyberSecure Dashboard",
    page_icon="📁",
    layout="wide"
)

def create_risk_gauge(risk_score, risk_level):
    """Create a risk gauge visualization"""
    color_map = {
        'LOW': '#28a745',
        'MEDIUM': '#ffc107',
        'HIGH': '#fd7e14',
        'CRITICAL': '#dc3545'
    }
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=risk_score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': f"Risk Level: {risk_level}"},
        gauge={
            'axis': {'range': [None, 100]},
            'bar': {'color': color_map.get(risk_level, '#28a745')},
            'steps': [
                {'range': [0, 25], 'color': "lightgray"},
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

def display_pe_analysis(pe_analysis):
    """Display PE file analysis results"""
    if not pe_analysis.get('is_pe'):
        st.info("File is not a PE (Portable Executable) file")
        return
    
    st.subheader("📋 PE File Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Basic PE Information:**")
        st.write(f"- Entry Point: `{pe_analysis.get('entry_point', 'N/A')}`")
        st.write(f"- Number of Sections: `{pe_analysis.get('number_of_sections', 'N/A')}`")
        st.write(f"- Timestamp: `{pe_analysis.get('timestamp', 'N/A')}`")
        st.write(f"- Machine Type: `{pe_analysis.get('machine_type', 'N/A')}`")
    
    with col2:
        if pe_analysis.get('suspicious_flags'):
            st.write("**⚠️ Suspicious Characteristics:**")
            for flag in pe_analysis['suspicious_flags']:
                st.warning(f"• {flag}")
        else:
            st.success("No suspicious PE characteristics detected")
    
    # Display sections
    if 'sections' in pe_analysis and pe_analysis['sections']:
        st.write("**PE Sections:**")
        sections_df = pd.DataFrame(pe_analysis['sections'])
        st.dataframe(sections_df, use_container_width=True)
        
        # Create entropy visualization
        if 'entropy' in sections_df.columns:
            fig = px.bar(
                sections_df, 
                x='name', 
                y='entropy',
                title='Section Entropy Analysis',
                color='entropy',
                color_continuous_scale='Reds'
            )
            fig.add_hline(y=7.0, line_dash="dash", line_color="red", 
                         annotation_text="High Entropy Threshold (7.0)")
            st.plotly_chart(fig, use_container_width=True)

def display_yara_results(yara_results):
    """Display YARA scan results"""
    st.subheader("🔍 YARA Rule Matches")
    
    if yara_results.get('error'):
        st.error(f"YARA scan error: {yara_results['error']}")
        return
    
    matches = yara_results.get('matches', [])
    if not matches:
        st.success("✅ No YARA rules matched - No known malware patterns detected")
        return
    
    st.warning(f"⚠️ {len(matches)} YARA rule(s) matched")
    
    for match in matches:
        with st.expander(f"🚨 Rule: {match.get('rule', 'Unknown')}", expanded=True):
            meta = match.get('meta', {})
            if meta.get('description'):
                st.write(f"**Description:** {meta['description']}")
            
            strings = match.get('strings', [])
            if strings:
                st.write("**Matched Strings:**")
                for string_match in strings:
                    st.write(f"- `{string_match.get('identifier', 'N/A')}`: {string_match.get('instances', 0)} instances")

def display_ml_results(ml_results):
    """Display machine learning analysis results"""
    st.subheader("🤖 AI/ML Threat Detection")
    
    if ml_results.get('error'):
        st.error(f"ML analysis error: {ml_results['error']}")
        return
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        malware_prob = ml_results.get('malware_probability', 0)
        st.metric(
            "Malware Probability",
            f"{malware_prob:.1%}",
            delta=f"Confidence: {ml_results.get('confidence', 0):.1%}"
        )
    
    with col2:
        prediction = "MALWARE" if ml_results.get('malware_prediction', False) else "CLEAN"
        color = "🔴" if prediction == "MALWARE" else "🟢"
        st.metric("ML Prediction", f"{color} {prediction}")
    
    with col3:
        anomaly_status = "ANOMALY" if ml_results.get('is_anomaly', False) else "NORMAL"
        anomaly_color = "🟠" if anomaly_status == "ANOMALY" else "🟢"
        st.metric("Anomaly Detection", f"{anomaly_color} {anomaly_status}")
    
    # Feature importance
    if 'feature_importance' in ml_results:
        st.write("**Feature Importance:**")
        importance_df = pd.DataFrame([
            {'Feature': k, 'Importance': v} 
            for k, v in ml_results['feature_importance'].items()
        ]).sort_values('Importance', ascending=False)
        
        fig = px.bar(
            importance_df.head(10), 
            x='Importance', 
            y='Feature',
            orientation='h',
            title='Top 10 Features for ML Prediction'
        )
        st.plotly_chart(fig, use_container_width=True)

def display_threat_intel_results(threat_intel):
    """Display threat intelligence results"""
    st.subheader("🌐 Threat Intelligence Lookup")
    
    if threat_intel.get('error'):
        st.error(f"Threat intelligence error: {threat_intel['error']}")
        return
    
    if not threat_intel.get('found'):
        st.info("File hash not found in threat intelligence databases")
        return
    
    reputation = threat_intel.get('reputation', {})
    level = reputation.get('level', 'UNKNOWN')
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        level_colors = {
            'MALICIOUS': '🔴',
            'SUSPICIOUS': '🟠',
            'QUESTIONABLE': '🟡',
            'CLEAN': '🟢',
            'UNKNOWN': '⚪'
        }
        st.metric("Reputation", f"{level_colors.get(level, '⚪')} {level}")
    
    with col2:
        detection_ratio = threat_intel.get('detection_ratio', 'N/A')
        st.metric("Detection Ratio", detection_ratio)
    
    with col3:
        source = threat_intel.get('source', 'Unknown')
        st.metric("Source", source)
    
    # Detection stats
    if 'detection_stats' in threat_intel:
        stats = threat_intel['detection_stats']
        st.write("**Detection Statistics:**")
        
        stats_df = pd.DataFrame([
            {'Category': 'Malicious', 'Count': stats.get('malicious', 0)},
            {'Category': 'Suspicious', 'Count': stats.get('suspicious', 0)},
            {'Category': 'Undetected', 'Count': stats.get('undetected', 0)},
            {'Category': 'Harmless', 'Count': stats.get('harmless', 0)}
        ])
        
        fig = px.pie(
            stats_df, 
            values='Count', 
            names='Category',
            title='Threat Intelligence Detection Results',
            color_discrete_map={
                'Malicious': '#dc3545',
                'Suspicious': '#fd7e14',
                'Undetected': '#6c757d',
                'Harmless': '#28a745'
            }
        )
        st.plotly_chart(fig, use_container_width=True)

def main():
    """Main file analysis interface"""
    st.title("📁 File Analysis & Malware Detection")
    st.markdown("Upload files for comprehensive security analysis using AI/ML models and threat intelligence")
    
    # Initialize analyzers
    analyzers = init_analyzers()
    if not analyzers:
        st.stop()
    
    # File upload section
    st.subheader("📤 File Upload")
    uploaded_file = st.file_uploader(
        "Choose a file to analyze",
        type=['exe', 'dll', 'pdf', 'doc', 'docx', 'zip', 'rar', 'txt', 'js', 'py'],
        help="Supported formats: .exe, .dll, .pdf, .doc, .docx, .zip, .rar, .txt, .js, .py"
    )
    
    if uploaded_file is not None:
        # Display file information
        st.success(f"File uploaded: {uploaded_file.name}")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("File Size", f"{len(uploaded_file.getvalue()):,} bytes")
        with col2:
            st.metric("File Type", uploaded_file.type)
        with col3:
            if st.button("🔍 Start Analysis", type="primary", use_container_width=True):
                st.session_state.analyze_file = True
        
        # Perform analysis if requested
        if st.session_state.get('analyze_file', False):
            st.divider()
            
            # Analysis progress
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            try:
                # Step 1: File Analysis
                status_text.text("🔍 Analyzing file structure and properties...")
                progress_bar.progress(20)
                
                file_results = analyzers['file_analyzer'].comprehensive_analysis(uploaded_file)
                
                if file_results.get('status') == 'error':
                    st.error(f"File analysis failed: {file_results.get('error')}")
                    st.stop()
                
                # Step 2: ML Analysis
                status_text.text("🤖 Running AI/ML threat detection...")
                progress_bar.progress(40)
                
                ml_results = analyzers['ml_detector'].predict_malware(file_results)
                
                # Step 3: Threat Intelligence
                status_text.text("🌐 Checking threat intelligence databases...")
                progress_bar.progress(60)
                
                threat_intel_results = None
                if 'hashes' in file_results:
                    sha256_hash = file_results['hashes'].get('sha256')
                    if sha256_hash:
                        threat_intel_results = analyzers['threat_intel'].lookup_file_hash(sha256_hash, 'sha256')
                
                # Step 4: Generate Report
                status_text.text("📊 Generating analysis report...")
                progress_bar.progress(80)
                
                report = analyzers['report_generator'].generate_file_analysis_report(
                    file_results, ml_results, threat_intel_results
                )
                
                progress_bar.progress(100)
                status_text.text("✅ Analysis complete!")
                
                time.sleep(1)  # Brief pause before showing results
                
                # Clear progress indicators
                progress_bar.empty()
                status_text.empty()
                
                # Display results
                st.success("🎯 Analysis Complete!")
                
                # Risk assessment overview
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.subheader("📊 Risk Assessment Summary")
                    
                    summary = report.get('summary', {})
                    
                    metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
                    
                    with metric_col1:
                        st.metric("Total Findings", summary.get('total_findings', 0))
                    with metric_col2:
                        st.metric("Critical Issues", summary.get('critical_findings', 0))
                    with metric_col3:
                        st.metric("High Priority", summary.get('high_findings', 0))
                    with metric_col4:
                        st.metric("Medium Priority", summary.get('medium_findings', 0))
                    
                    # Recommendations
                    if 'recommendations' in report:
                        st.write("**🎯 Key Recommendations:**")
                        for i, rec in enumerate(report['recommendations'][:3], 1):
                            st.write(f"{i}. {rec}")
                
                with col2:
                    # Risk gauge
                    risk_assessment = report.get('risk_assessment', {})
                    risk_score = risk_assessment.get('risk_score', 0)
                    risk_level = risk_assessment.get('risk_level', 'UNKNOWN')
                    
                    fig_gauge = create_risk_gauge(risk_score, risk_level)
                    st.plotly_chart(fig_gauge, use_container_width=True)
                
                st.divider()
                
                # Detailed analysis results in tabs
                tab1, tab2, tab3, tab4, tab5 = st.tabs([
                    "📋 File Details", 
                    "🔍 Static Analysis", 
                    "🤖 AI/ML Detection",
                    "🌐 Threat Intelligence",
                    "📊 Full Report"
                ])
                
                with tab1:
                    st.subheader("📁 File Information")
                    
                    file_details = report.get('file_details', {})
                    
                    detail_col1, detail_col2 = st.columns(2)
                    
                    with detail_col1:
                        st.write("**Basic Information:**")
                        st.write(f"- **Filename:** {file_details.get('filename', 'N/A')}")
                        st.write(f"- **File Size:** {file_details.get('file_size', 0):,} bytes")
                        st.write(f"- **File Type:** {file_details.get('file_type', 'N/A')}")
                        st.write(f"- **MIME Type:** {file_details.get('mime_type', 'N/A')}")
                    
                    with detail_col2:
                        if 'hashes' in file_details:
                            st.write("**File Hashes:**")
                            hashes = file_details['hashes']
                            st.code(f"MD5:    {hashes.get('md5', 'N/A')}")
                            st.code(f"SHA1:   {hashes.get('sha1', 'N/A')}")
                            st.code(f"SHA256: {hashes.get('sha256', 'N/A')}")
                
                with tab2:
                    # PE Analysis
                    if 'pe_analysis' in file_results:
                        display_pe_analysis(file_results['pe_analysis'])
                    
                    # YARA Results
                    if 'yara_scan' in file_results:
                        display_yara_results(file_results['yara_scan'])
                
                with tab3:
                    display_ml_results(ml_results)
                
                with tab4:
                    if threat_intel_results:
                        display_threat_intel_results(threat_intel_results)
                    else:
                        st.info("No threat intelligence data available")
                
                with tab5:
                    st.subheader("📊 Complete Analysis Report")
                    
                    # Report download
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.write("**Report Summary:**")
                        st.write(f"- Generated: {report.get('generated_at', 'Unknown')}")
                        st.write(f"- Report Type: {report.get('report_type', 'Unknown')}")
                        st.write(f"- Risk Level: {risk_level}")
                    
                    with col2:
                        # Export report
                        report_json = analyzers['report_generator'].export_report_to_json(report)
                        st.download_button(
                            label="📥 Download Report (JSON)",
                            data=report_json,
                            file_name=f"file_analysis_report_{uploaded_file.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                            mime="application/json",
                            use_container_width=True
                        )
                    
                    # Full report details
                    st.json(report)
                
                # Update session state
                if 'scan_history' not in st.session_state:
                    st.session_state.scan_history = []
                
                st.session_state.scan_history.append({
                    'time': datetime.now().strftime("%H:%M:%S"),
                    'action': 'File Analysis',
                    'result': 'threat' if risk_level in ['CRITICAL', 'HIGH'] else 'clean',
                    'details': f"Analyzed {uploaded_file.name} - Risk: {risk_level}"
                })
                
                # Update global metrics
                st.session_state.total_scans = st.session_state.get('total_scans', 0) + 1
                if risk_level in ['CRITICAL', 'HIGH']:
                    st.session_state.threats_detected = st.session_state.get('threats_detected', 0) + 1
                    st.session_state.threat_level = 'HIGH' if risk_level == 'HIGH' else 'CRITICAL'
                
                # Clear analysis flag
                st.session_state.analyze_file = False
                
            except Exception as e:
                progress_bar.empty()
                status_text.empty()
                st.error(f"Analysis failed: {str(e)}")
                st.session_state.analyze_file = False
    
    else:
        # Instructions when no file is uploaded
        st.info("👆 Please upload a file to begin analysis")
        
        with st.expander("ℹ️ Analysis Features", expanded=True):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Static Analysis:**")
                st.write("• File hash calculation (MD5, SHA1, SHA256)")
                st.write("• PE file structure analysis")
                st.write("• YARA rule matching")
                st.write("• File entropy analysis")
            
            with col2:
                st.write("**AI/ML Detection:**")
                st.write("• Machine learning malware detection")
                st.write("• Anomaly detection algorithms")
                st.write("• Feature importance analysis")
                st.write("• Threat intelligence integration")

if __name__ == "__main__":
    main()
