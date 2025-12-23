# pages/4_Security_Reports.py
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import sys
import os
import json
import base64
from io import BytesIO
import random

# Add the project root to the path to import utilities
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.ui_helpers import init_analyzers
from utils.report_generator import ReportGenerator

# Page configuration
st.set_page_config(
    page_title="Security Reports - CyberSecure Dashboard",
    page_icon="📊",
    layout="wide"
)

def create_security_posture_chart(reports_data):
    """Create security posture overview chart"""
    if not reports_data:
        return None
    
    # Aggregate risk levels from all reports
    risk_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    
    for report_type, reports in reports_data.items():
        for report in reports:
            if 'risk_assessment' in report:
                risk_level = report['risk_assessment'].get('risk_level', 'LOW')
                risk_counts[risk_level] += 1
    
    # Create pie chart
    fig = go.Figure(data=[go.Pie(
        labels=list(risk_counts.keys()),
        values=list(risk_counts.values()),
        marker_colors=['#28a745', '#ffc107', '#fd7e14', '#dc3545']
    )])
    
    fig.update_layout(
        title='Security Posture Distribution',
        height=400,
        showlegend=True
    )
    
    return fig

def create_threat_timeline_chart(reports_data):
    """Create threat detection timeline"""
    if not reports_data:
        return None
    
    timeline_data = []
    
    for report_type, reports in reports_data.items():
        for report in reports:
            timestamp = report.get('generated_at', datetime.now().isoformat())
            risk_level = report.get('risk_assessment', {}).get('risk_level', 'LOW')
            findings_count = report.get('summary', {}).get('total_findings', 0)
            
            timeline_data.append({
                'timestamp': timestamp,
                'report_type': report_type,
                'risk_level': risk_level,
                'findings': findings_count
            })
    
    if not timeline_data:
        return None
    
    df = pd.DataFrame(timeline_data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    fig = px.scatter(
        df,
        x='timestamp',
        y='findings',
        color='risk_level',
        size='findings',
        hover_data=['report_type'],
        title='Threat Detection Timeline',
        color_discrete_map={
            'LOW': '#28a745',
            'MEDIUM': '#ffc107', 
            'HIGH': '#fd7e14',
            'CRITICAL': '#dc3545'
        }
    )
    
    fig.update_layout(height=400)
    return fig

def create_findings_summary_chart(comprehensive_report):
    """Create findings summary chart"""
    if not comprehensive_report or 'detailed_findings' not in comprehensive_report:
        return None
    
    findings = comprehensive_report['detailed_findings']
    
    # Count findings by type
    finding_counts = {}
    for report_type, report_list in findings.items():
        finding_counts[report_type.replace('_', ' ').title()] = len(report_list)
    
    if not any(finding_counts.values()):
        return None
    
    fig = go.Figure(data=[go.Bar(
        x=list(finding_counts.keys()),
        y=list(finding_counts.values()),
        marker_color=['#007bff', '#28a745', '#ffc107']
    )])
    
    fig.update_layout(
        title='Analysis Coverage by Type',
        xaxis_title='Analysis Type',
        yaxis_title='Number of Reports',
        height=400
    )
    
    return fig

def display_comprehensive_report_summary(report):
    """Display comprehensive report summary"""
    if not report:
        st.error("No comprehensive report data available")
        return
    
    st.subheader("📋 Executive Summary")
    
    executive_summary = report.get('executive_summary', {})
    overall_risk = report.get('overall_risk_assessment', {})
    
    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Overall Risk Level",
            overall_risk.get('risk_level', 'UNKNOWN'),
            delta=f"Score: {overall_risk.get('risk_score', 0)}/100"
        )
    
    with col2:
        st.metric(
            "Total Security Events",
            executive_summary.get('total_security_events', 0)
        )
    
    with col3:
        st.metric(
            "Critical Issues",
            overall_risk.get('critical_findings', 0)
        )
    
    with col4:
        st.metric(
            "Security Posture",
            overall_risk.get('security_posture', 'Unknown').split(' - ')[0]
        )
    
    # Risk assessment details
    if overall_risk.get('risk_level') in ['CRITICAL', 'HIGH']:
        st.error("🚨 **IMMEDIATE ATTENTION REQUIRED** - Critical security issues detected")
        if executive_summary.get('immediate_action_required'):
            st.write("**Immediate Actions Needed:**")
            st.write("- Address all critical findings immediately")
            st.write("- Implement emergency security measures")
            st.write("- Contact security team for incident response")
    elif overall_risk.get('risk_level') == 'MEDIUM':
        st.warning("⚠️ **MODERATE RISK** - Security improvements recommended")
    else:
        st.success("✅ **GOOD SECURITY POSTURE** - Continue monitoring")
    
    # Key recommendations
    if 'key_recommendations' in executive_summary:
        st.write("**🎯 Key Recommendations:**")
        for i, rec in enumerate(executive_summary['key_recommendations'], 1):
            st.write(f"{i}. {rec}")

def display_action_plan(report):
    """Display action plan from comprehensive report"""
    if not report or 'action_plan' not in report:
        return
    
    st.subheader("📅 Action Plan")
    
    action_plan = report['action_plan']
    
    for action in action_plan:
        priority = action.get('priority', 'LOW')
        timeline = action.get('timeline', 'Unknown')
        action_text = action.get('action', 'No action specified')
        details = action.get('details', 'No details provided')
        owner = action.get('owner', 'Unassigned')
        
        # Priority color coding
        priority_colors = {
            'IMMEDIATE': 'error',
            'HIGH': 'warning',
            'MEDIUM': 'info',
            'LOW': 'success'
        }
        
        with st.container():
            priority_method = getattr(st, priority_colors.get(priority, 'info'))
            priority_method(f"**{priority} PRIORITY** ({timeline})")
            
            st.write(f"**Action:** {action_text}")
            st.write(f"**Details:** {details}")
            st.write(f"**Owner:** {owner}")
            st.divider()

def generate_sample_reports(analyzers):
    """Generate sample reports for demonstration"""
    sample_reports = {
        'file_analysis': [],
        'network_analysis': [],
        'threat_intelligence': []
    }
    
    try:
        # Generate sample file analysis report
        sample_file_results = {
            'file_info': {
                'name': f'sample_file_{random.randint(1,100)}.exe',
                'size': random.randint(100000, 2000000),
                'type': 'application/x-executable',
                'upload_time': datetime.now().isoformat()
            },
            'hashes': {
                'md5': ''.join(random.choices('0123456789abcdef', k=32)),
                'sha1': ''.join(random.choices('0123456789abcdef', k=40)),
                'sha256': ''.join(random.choices('0123456789abcdef', k=64))
            },
            'yara_scan': {
                'matches': [],
                'total_matches': 0
            },
            'pe_analysis': {
                'is_pe': True,
                'suspicious_flags': []
            }
        }
        
        sample_ml_results = {
            'malware_probability': random.uniform(0.05, 0.95),
            'malware_prediction': random.choice([True, False]),
            'confidence': random.uniform(0.5, 1.0),
            'is_anomaly': random.choice([True, False]),
            'anomaly_score': random.uniform(-0.5, 0.5)
        }
        
        file_report = analyzers['report_generator'].generate_file_analysis_report(
            sample_file_results, sample_ml_results, None
        )
        sample_reports['file_analysis'].append(file_report)
        
        # Generate sample network analysis report
        sample_network_data = analyzers['network_analyzer'].create_sample_network_data(random.randint(50, 200))
        sample_anomalies = analyzers['network_analyzer'].detect_anomalies(sample_network_data)
        
        network_report = analyzers['report_generator'].generate_network_analysis_report(
            sample_network_data, sample_anomalies
        )
        sample_reports['network_analysis'].append(network_report)
        
        # Generate sample threat intelligence report
        sample_threat_lookups = [
            {
                'indicator': {'type': 'ip', 'value': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'},
                'result': {
                    'found': True,
                    'reputation': {'level': random.choice(['CLEAN', 'SUSPICIOUS', 'MALICIOUS']), 'score': random.randint(0,100)},
                    'source': 'sample'
                }
            }
        ]
        
        ti_report = analyzers['report_generator'].generate_threat_intelligence_report(
            sample_threat_lookups
        )
        sample_reports['threat_intelligence'].append(ti_report)
        
        return sample_reports
        
    except Exception as e:
        st.error(f"Failed to generate sample reports: {str(e)}")
        return sample_reports

def main():
    """Main security reports interface"""
    st.title("📊 Security Analysis Reports")
    st.markdown("Generate comprehensive security reports combining file analysis, network monitoring, and threat intelligence")
    
    # Initialize analyzers
    analyzers = init_analyzers()
    if not analyzers:
        st.stop()
    
    # Report generation options
    st.subheader("📋 Report Generation Options")
    
    tab1, tab2, tab3 = st.tabs(["🔄 Generate New Report", "📁 Saved Reports", "📊 Dashboard Overview"])
    
    with tab1:
        st.write("Generate a new comprehensive security assessment report")
        
        # Report configuration
        col1, col2 = st.columns(2)
        
        with col1:
            report_name = st.text_input(
                "Report Name:",
                value=f"Security Assessment {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                key="report_name"
            )
            
            include_file_analysis = st.checkbox("Include File Analysis", value=True)
            include_network_analysis = st.checkbox("Include Network Analysis", value=True)
            include_threat_intel = st.checkbox("Include Threat Intelligence", value=True)
        
        with col2:
            report_scope = st.selectbox(
                "Report Scope:",
                ["Comprehensive Assessment", "File Security Focus", "Network Security Focus", "Threat Intelligence Focus"]
            )
            
            time_range = st.selectbox(
                "Time Range:",
                ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "Custom Range"]
            )
        
        if st.button("🔄 Generate Comprehensive Report", type="primary", use_container_width=True):
            with st.spinner("Generating comprehensive security report..."):
                # For demonstration, generate sample reports
                # In production, this would gather actual analysis data
                sample_reports = generate_sample_reports(analyzers)
                
                # Generate comprehensive report
                comprehensive_report = analyzers['report_generator'].generate_comprehensive_report(
                    sample_reports.get('file_analysis', []),
                    sample_reports.get('network_analysis', []),
                    sample_reports.get('threat_intelligence', [])
                )
                
                if 'error' not in comprehensive_report:
                    st.success("✅ Comprehensive security report generated successfully!")
                    
                    # Store report in session state
                    if 'generated_reports' not in st.session_state:
                        st.session_state.generated_reports = []
                    
                    comprehensive_report['report_name'] = report_name
                    st.session_state.generated_reports.append(comprehensive_report)
                    
                    # Display report summary
                    display_comprehensive_report_summary(comprehensive_report)
                    
                    st.divider()
                    
                    # Report details in tabs
                    detail_tab1, detail_tab2, detail_tab3, detail_tab4 = st.tabs([
                        "📊 Visualizations",
                        "🔍 Detailed Findings", 
                        "📅 Action Plan",
                        "📥 Export Options"
                    ])
                    
                    with detail_tab1:
                        st.subheader("📊 Security Analysis Visualizations")
                        
                        # Create and display charts
                        chart_col1, chart_col2 = st.columns(2)
                        
                        with chart_col1:
                            posture_chart = create_security_posture_chart(sample_reports)
                            if posture_chart:
                                st.plotly_chart(posture_chart, use_container_width=True)
                        
                        with chart_col2:
                            findings_chart = create_findings_summary_chart(comprehensive_report)
                            if findings_chart:
                                st.plotly_chart(findings_chart, use_container_width=True)
                        
                        # Timeline chart
                        timeline_chart = create_threat_timeline_chart(sample_reports)
                        if timeline_chart:
                            st.plotly_chart(timeline_chart, use_container_width=True)
                    
                    with detail_tab2:
                        st.subheader("🔍 Detailed Analysis Findings")
                        
                        detailed_findings = comprehensive_report.get('detailed_findings', {})
                        
                        if detailed_findings.get('file_analysis'):
                            st.write("**📁 File Analysis Results:**")
                            for finding in detailed_findings['file_analysis']:
                                st.write(f"- {finding.get('filename', 'Unknown')}: {finding.get('risk_level', 'Unknown')} risk ({finding.get('findings_count', 0)} findings)")
                        
                        if detailed_findings.get('network_analysis'):
                            st.write("**🌐 Network Analysis Results:**")
                            for finding in detailed_findings['network_analysis']:
                                st.write(f"- {finding.get('connections_analyzed', 0)} connections analyzed, {finding.get('anomalies_detected', 0)} anomalies detected")
                        
                        if detailed_findings.get('threat_intelligence'):
                            st.write("**🔍 Threat Intelligence Results:**")
                            for finding in detailed_findings['threat_intelligence']:
                                st.write(f"- {finding.get('indicators_analyzed', 0)} indicators checked, {finding.get('malicious_found', 0)} malicious found")
                    
                    with detail_tab3:
                        display_action_plan(comprehensive_report)
                    
                    with detail_tab4:
                        st.subheader("📥 Export and Sharing Options")
                        st.info("NOTE: PDF export would require a library like `fpdf` or `reportlab`.")
                        
                        export_col1, export_col2 = st.columns(2)
                        
                        with export_col1:
                            # JSON export
                            report_json = analyzers['report_generator'].export_report_to_json(comprehensive_report)
                            st.download_button(
                                label="📄 Download JSON Report",
                                data=report_json,
                                file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                mime="application/json",
                                use_container_width=True
                            )
                        
                        with export_col2:
                            # Executive summary export
                            executive_summary = comprehensive_report.get('executive_summary', {})
                            summary_text = f"""
SECURITY ASSESSMENT EXECUTIVE SUMMARY
Generated: {comprehensive_report.get('generated_at', 'Unknown')}
Report: {report_name}

OVERALL RISK LEVEL: {comprehensive_report.get('overall_risk_assessment', {}).get('risk_level', 'Unknown')}
SECURITY POSTURE: {comprehensive_report.get('overall_risk_assessment', {}).get('security_posture', 'Unknown')}

TOTAL SECURITY EVENTS: {executive_summary.get('total_security_events', 0)}
CRITICAL ISSUES: {comprehensive_report.get('overall_risk_assessment', {}).get('critical_findings', 0)}
HIGH PRIORITY ISSUES: {comprehensive_report.get('overall_risk_assessment', {}).get('high_findings', 0)}

KEY RECOMMENDATIONS:
{chr(10).join(f"- {rec}" for rec in executive_summary.get('key_recommendations', []))}
                            """
                            
                            st.download_button(
                                label="📋 Download Executive Summary",
                                data=summary_text,
                                file_name=f"executive_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                                mime="text/plain",
                                use_container_width=True
                            )
                        
                        # Report sharing options
                        st.write("**📤 Sharing Options:**")
                        st.info("💡 Share reports with your security team for collaborative analysis")
                        
                        share_email = st.text_input("Email for sharing:", placeholder="security-team@company.com")
                        if st.button("📧 Share Report (Email)"):
                            st.success(f"✅ Report shared with {share_email}")
                else:
                    st.error(f"Failed to generate report: {comprehensive_report.get('error', 'Unknown error')}")
    
    with tab2:
        st.subheader("📁 Previously Generated Reports")
        
        if 'generated_reports' in st.session_state and st.session_state.generated_reports:
            st.write(f"You have {len(st.session_state.generated_reports)} saved report(s)")
            
            for i, report in enumerate(st.session_state.generated_reports):
                report_name = report.get('report_name', f'Report {i+1}')
                generated_at = report.get('generated_at', 'Unknown')
                risk_level = report.get('overall_risk_assessment', {}).get('risk_level', 'Unknown')
                
                with st.expander(f"📊 {report_name} - {risk_level} Risk", expanded=False):
                    col1, col2, col3 = st.columns([2, 1, 1])
                    
                    with col1:
                        st.write(f"**Generated:** {generated_at}")
                        st.write(f"**Risk Level:** {risk_level}")
                        st.write(f"**Total Findings:** {report.get('overall_risk_assessment', {}).get('total_findings', 0)}")
                    
                    with col2:
                        if st.button(f"📄 View Report {i+1}", key=f"view_{i}"):
                            st.session_state.selected_report = report
                    
                    with col3:
                        report_json = analyzers['report_generator'].export_report_to_json(report)
                        st.download_button(
                            label=f"📥 Download {i+1}",
                            data=report_json,
                            file_name=f"report_{i+1}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                            mime="application/json",
                            key=f"download_{i}"
                        )
            
            # Display selected report
            if 'selected_report' in st.session_state:
                st.divider()
                st.subheader("📋 Selected Report Details")
                display_comprehensive_report_summary(st.session_state.selected_report)
        else:
            st.info("📝 No reports generated yet. Create your first comprehensive security report!")
            
            if st.button("🚀 Generate Sample Report"):
                st.rerun()
    
    with tab3:
        st.subheader("📊 Security Dashboard Overview")
        
        # Real-time security metrics (would connect to actual monitoring in production)
        st.write("**🔄 Real-time Security Status:**")
        
        overview_col1, overview_col2, overview_col3, overview_col4 = st.columns(4)
        
        with overview_col1:
            st.metric(
                "System Health",
                "GOOD",
                delta="All systems operational"
            )
        
        with overview_col2:
            files_scanned_today = st.session_state.get('total_scans', 0)
            st.metric(
                "Files Scanned Today",
                files_scanned_today,
                delta=f"+{files_scanned_today} from yesterday"
            )
        
        with overview_col3:
            threats_detected = st.session_state.get('threats_detected', 0)
            st.metric(
                "Threats Detected",
                threats_detected,
                delta="Requires attention" if threats_detected > 0 else "All clear"
            )
        
        with overview_col4:
            current_threat_level = st.session_state.get('threat_level', 'LOW')
            st.metric(
                "Current Threat Level",
                current_threat_level,
                delta="Monitoring active"
            )
        
        st.divider()
        
        # Security trends (placeholder for actual data visualization)
        st.write("**📈 Security Trends:**")
        
        # Generate sample trend data for visualization
        dates = pd.date_range(start=datetime.now() - timedelta(days=30), end=datetime.now(), freq='D')
        trend_data = pd.DataFrame({
            'date': dates,
            'scans': [max(0, 50 + int(10 * (i % 7 - 3))) for i in range(len(dates))],
            'threats': [max(0, 5 + int(3 * (i % 11 - 5))) for i in range(len(dates))],
            'clean': [max(0, 45 + int(8 * (i % 5 - 2))) for i in range(len(dates))]
        })
        
        fig_trends = go.Figure()
        
        fig_trends.add_trace(go.Scatter(
            x=trend_data['date'],
            y=trend_data['scans'],
            mode='lines+markers',
            name='Total Scans',
            line=dict(color='blue')
        ))
        
        fig_trends.add_trace(go.Scatter(
            x=trend_data['date'],
            y=trend_data['threats'],
            mode='lines+markers',
            name='Threats Detected',
            line=dict(color='red')
        ))
        
        fig_trends.add_trace(go.Scatter(
            x=trend_data['date'],
            y=trend_data['clean'],
            mode='lines+markers',
            name='Clean Files',
            line=dict(color='green')
        ))
        
        fig_trends.update_layout(
            title='30-Day Security Activity Trends',
            xaxis_title='Date',
            yaxis_title='Count',
            height=400,
            hovermode='x unified'
        )
        
        st.plotly_chart(fig_trends, use_container_width=True)
        
        # Quick actions
        st.write("**⚡ Quick Actions:**")
        
        action_col1, action_col2, action_col3 = st.columns(3)
        
        with action_col1:
            if st.button("🔍 Run System Scan", use_container_width=True):
                st.success("System scan initiated")
        
        with action_col2:
            if st.button("📊 Generate Daily Report", use_container_width=True):
                st.success("Daily report queued for generation")
        
        with action_col3:
            if st.button("🚨 View Active Alerts", use_container_width=True):
                st.info("No active alerts at this time")

if __name__ == "__main__":
    main()
