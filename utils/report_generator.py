# utils/report_generator.py
import pandas as pd
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from io import BytesIO
import base64

class ReportGenerator:
    """Generate comprehensive security analysis reports"""
    
    def __init__(self):
        """Initialize report generator"""
        self.report_templates = {
            'file_analysis': 'File Analysis Report',
            'network_analysis': 'Network Security Analysis',
            'threat_intelligence': 'Threat Intelligence Report',
            'comprehensive': 'Comprehensive Security Assessment'
        }
    
    def generate_file_analysis_report(self, file_results: Dict, ml_results: Dict, threat_intel: Dict) -> Dict:
        """Generate file analysis report"""
        try:
            report = {
                'report_type': 'file_analysis',
                'title': 'File Analysis Security Report',
                'generated_at': datetime.now().isoformat(),
                'summary': {},
                'file_details': {},
                'security_analysis': {},
                'recommendations': [],
                'risk_assessment': {}
            }
            
            # Extract file information
            if 'file_info' in file_results:
                file_info = file_results['file_info']
                report['file_details'] = {
                    'filename': file_info.get('name', 'Unknown'),
                    'file_size': file_info.get('size', 0),
                    'file_type': file_info.get('file_type', 'Unknown'),
                    'mime_type': file_info.get('mime_type', 'Unknown'),
                    'upload_time': file_info.get('upload_time', 'Unknown')
                }
            
            # Hash analysis
            if 'hashes' in file_results:
                hashes = file_results['hashes']
                report['file_details']['hashes'] = {
                    'md5': hashes.get('md5', 'N/A'),
                    'sha1': hashes.get('sha1', 'N/A'),
                    'sha256': hashes.get('sha256', 'N/A')
                }
            
            # Security analysis results
            security_findings = []
            
            # YARA scan results
            if 'yara_scan' in file_results:
                yara_results = file_results['yara_scan']
                if yara_results.get('matches'):
                    for match in yara_results['matches']:
                        security_findings.append({
                            'type': 'YARA Detection',
                            'severity': 'HIGH',
                            'rule': match.get('rule', 'Unknown'),
                            'description': match.get('meta', {}).get('description', 'Malicious pattern detected')
                        })
            
            # PE analysis results
            if 'pe_analysis' in file_results and file_results['pe_analysis'].get('is_pe'):
                pe_analysis = file_results['pe_analysis']
                if pe_analysis.get('suspicious_flags'):
                    for flag in pe_analysis['suspicious_flags']:
                        security_findings.append({
                            'type': 'PE Analysis',
                            'severity': 'MEDIUM',
                            'description': flag
                        })
            
            # ML analysis results
            if ml_results and not ml_results.get('error'):
                malware_prob = ml_results.get('malware_probability', 0)
                if malware_prob > 0.7:
                    security_findings.append({
                        'type': 'ML Detection',
                        'severity': 'HIGH',
                        'description': f'High malware probability: {malware_prob:.2%}',
                        'confidence': ml_results.get('confidence', 0)
                    })
                elif malware_prob > 0.4:
                    security_findings.append({
                        'type': 'ML Detection',
                        'severity': 'MEDIUM',
                        'description': f'Moderate malware probability: {malware_prob:.2%}',
                        'confidence': ml_results.get('confidence', 0)
                    })
                
                if ml_results.get('is_anomaly'):
                    security_findings.append({
                        'type': 'Anomaly Detection',
                        'severity': 'MEDIUM',
                        'description': 'File characteristics are anomalous',
                        'anomaly_score': ml_results.get('anomaly_score', 0)
                    })
            
            # Threat intelligence results
            if threat_intel and not threat_intel.get('error'):
                reputation = threat_intel.get('reputation', {})
                if reputation.get('level') in ['MALICIOUS', 'SUSPICIOUS']:
                    security_findings.append({
                        'type': 'Threat Intelligence',
                        'severity': 'CRITICAL' if reputation.get('level') == 'MALICIOUS' else 'HIGH',
                        'description': f'File hash flagged as {reputation.get("level").lower()}',
                        'detection_ratio': threat_intel.get('detection_ratio', 'N/A'),
                        'engines_detected': reputation.get('harmful_detections', 0)
                    })
            
            report['security_analysis'] = {
                'total_findings': len(security_findings),
                'findings': security_findings,
                'overall_risk': self._calculate_overall_risk(security_findings, file_results, ml_results)
            }
            
            # Generate recommendations
            report['recommendations'] = self._generate_file_recommendations(security_findings, file_results, ml_results)
            
            # Risk assessment
            report['risk_assessment'] = self._generate_risk_assessment(security_findings, file_results, ml_results)
            
            # Summary
            report['summary'] = {
                'total_findings': len(security_findings),
                'critical_findings': len([f for f in security_findings if f.get('severity') == 'CRITICAL']),
                'high_findings': len([f for f in security_findings if f.get('severity') == 'HIGH']),
                'medium_findings': len([f for f in security_findings if f.get('severity') == 'MEDIUM']),
                'overall_risk_level': report['risk_assessment']['risk_level'],
                'recommended_action': report['risk_assessment']['recommended_action']
            }
            
            return report
            
        except Exception as e:
            return {
                'error': f'Failed to generate file analysis report: {str(e)}',
                'report_type': 'file_analysis',
                'generated_at': datetime.now().isoformat()
            }
    
    def generate_network_analysis_report(self, network_data: List[Dict], anomalies: Dict) -> Dict:
        """Generate network analysis report"""
        try:
            report = {
                'report_type': 'network_analysis',
                'title': 'Network Security Analysis Report',
                'generated_at': datetime.now().isoformat(),
                'summary': {},
                'network_overview': {},
                'anomaly_analysis': {},
                'risk_assessment': {},
                'recommendations': []
            }
            
            if not network_data:
                report['error'] = 'No network data provided for analysis'
                return report
            
            # Network overview
            df = pd.DataFrame(network_data)
            
            report['network_overview'] = {
                'total_connections': len(network_data),
                'unique_remote_ips': df['remote_ip'].nunique() if 'remote_ip' in df.columns else 0,
                'unique_ports': df['remote_port'].nunique() if 'remote_port' in df.columns else 0,
                'time_period': {
                    'start': df['timestamp'].min() if 'timestamp' in df.columns else 'Unknown',
                    'end': df['timestamp'].max() if 'timestamp' in df.columns else 'Unknown'
                },
                'protocol_distribution': df['protocol'].value_counts().to_dict() if 'protocol' in df.columns else {},
                'data_transfer': {
                    'total_bytes_sent': int(df['bytes_sent'].sum()) if 'bytes_sent' in df.columns else 0,
                    'total_bytes_received': int(df['bytes_recv'].sum()) if 'bytes_recv' in df.columns else 0
                }
            }
            
            # High risk connections
            high_risk_connections = []
            if 'risk_score' in df.columns:
                high_risk_df = df[df['risk_score'] >= 70]
                for _, conn in high_risk_df.iterrows():
                    high_risk_connections.append({
                        'remote_ip': conn.get('remote_ip', 'Unknown'),
                        'remote_port': conn.get('remote_port', 0),
                        'risk_score': conn.get('risk_score', 0),
                        'protocol': conn.get('protocol', 'Unknown'),
                        'timestamp': conn.get('timestamp', 'Unknown')
                    })
            
            # Anomaly analysis
            anomaly_summary = {
                'total_anomalies': anomalies.get('anomaly_count', 0),
                'anomaly_percentage': anomalies.get('anomaly_percentage', 0),
                'anomaly_types': {},
                'critical_anomalies': []
            }
            
            if 'anomalies' in anomalies:
                for anomaly in anomalies['anomalies']:
                    anomaly_type = anomaly.get('type', 'Unknown')
                    if anomaly_type not in anomaly_summary['anomaly_types']:
                        anomaly_summary['anomaly_types'][anomaly_type] = 0
                    anomaly_summary['anomaly_types'][anomaly_type] += 1
                    
                    if anomaly.get('severity') == 'HIGH':
                        anomaly_summary['critical_anomalies'].append({
                            'type': anomaly_type,
                            'description': self._format_anomaly_description(anomaly),
                            'severity': anomaly.get('severity', 'UNKNOWN')
                        })
            
            report['anomaly_analysis'] = anomaly_summary
            
            # Risk assessment
            risk_factors = []
            risk_score = 0
            
            if anomaly_summary['total_anomalies'] > 0:
                risk_score += min(anomaly_summary['total_anomalies'] * 5, 50)
                risk_factors.append(f"{anomaly_summary['total_anomalies']} network anomalies detected")
            
            if len(high_risk_connections) > 0:
                risk_score += min(len(high_risk_connections) * 10, 40)
                risk_factors.append(f"{len(high_risk_connections)} high-risk connections")
            
            # Check for suspicious patterns
            if 'remote_country' in df.columns:
                unknown_countries = len(df[df['remote_country'] == 'Unknown'])
                if unknown_countries > len(df) * 0.2:  # More than 20% unknown
                    risk_score += 15
                    risk_factors.append("High percentage of connections to unknown locations")
            
            report['risk_assessment'] = {
                'risk_score': min(risk_score, 100),
                'risk_level': self._determine_risk_level(risk_score),
                'risk_factors': risk_factors,
                'recommended_action': self._get_network_recommended_action(risk_score)
            }
            
            # Generate recommendations
            report['recommendations'] = self._generate_network_recommendations(
                high_risk_connections, anomaly_summary, report['risk_assessment']
            )
            
            # Summary
            report['summary'] = {
                'total_connections': len(network_data),
                'anomalies_detected': anomaly_summary['total_anomalies'],
                'high_risk_connections': len(high_risk_connections),
                'overall_risk_level': report['risk_assessment']['risk_level'],
                'primary_concerns': risk_factors[:3]  # Top 3 concerns
            }
            
            return report
            
        except Exception as e:
            return {
                'error': f'Failed to generate network analysis report: {str(e)}',
                'report_type': 'network_analysis',
                'generated_at': datetime.now().isoformat()
            }
    
    def generate_threat_intelligence_report(self, threat_lookups: List[Dict]) -> Dict:
        """Generate threat intelligence report"""
        try:
            report = {
                'report_type': 'threat_intelligence',
                'title': 'Threat Intelligence Analysis Report',
                'generated_at': datetime.now().isoformat(),
                'summary': {},
                'indicators_analyzed': [],
                'threat_findings': [],
                'recommendations': []
            }
            
            if not threat_lookups:
                report['error'] = 'No threat intelligence data provided'
                return report
            
            malicious_indicators = []
            suspicious_indicators = []
            clean_indicators = []
            failed_lookups = []
            
            for lookup in threat_lookups:
                indicator_info = {
                    'indicator': lookup.get('indicator', {}),
                    'result': lookup.get('result', {})
                }
                
                result = lookup.get('result', {})
                if 'error' in result:
                    failed_lookups.append(indicator_info)
                    continue
                
                reputation = result.get('reputation', {})
                level = reputation.get('level', 'UNKNOWN')
                
                if level == 'MALICIOUS':
                    malicious_indicators.append(indicator_info)
                elif level in ['SUSPICIOUS', 'QUESTIONABLE']:
                    suspicious_indicators.append(indicator_info)
                elif level == 'CLEAN':
                    clean_indicators.append(indicator_info)
                
                report['indicators_analyzed'].append(indicator_info)
            
            # Threat findings
            for indicator_info in malicious_indicators:
                result = indicator_info['result']
                indicator = indicator_info['indicator']
                
                finding = {
                    'severity': 'CRITICAL',
                    'indicator_type': indicator.get('type', 'Unknown'),
                    'indicator_value': indicator.get('value', 'Unknown'),
                    'threat_type': 'Confirmed Malicious',
                    'detection_ratio': result.get('detection_ratio', 'N/A'),
                    'source': result.get('source', 'Unknown'),
                    'description': f"Indicator flagged as malicious by threat intelligence"
                }
                
                if 'detection_stats' in result:
                    stats = result['detection_stats']
                    finding['engines_detected'] = stats.get('malicious', 0) + stats.get('suspicious', 0)
                    finding['total_engines'] = sum(stats.values())
                
                report['threat_findings'].append(finding)
            
            for indicator_info in suspicious_indicators:
                result = indicator_info['result']
                indicator = indicator_info['indicator']
                
                finding = {
                    'severity': 'HIGH',
                    'indicator_type': indicator.get('type', 'Unknown'),
                    'indicator_value': indicator.get('value', 'Unknown'),
                    'threat_type': 'Suspicious Activity',
                    'detection_ratio': result.get('detection_ratio', 'N/A'),
                    'source': result.get('source', 'Unknown'),
                    'description': f"Indicator shows suspicious characteristics"
                }
                
                report['threat_findings'].append(finding)
            
            # Risk assessment
            total_indicators = len(report['indicators_analyzed'])
            malicious_count = len(malicious_indicators)
            suspicious_count = len(suspicious_indicators)
            
            risk_score = 0
            if total_indicators > 0:
                malicious_ratio = malicious_count / total_indicators
                suspicious_ratio = suspicious_count / total_indicators
                risk_score = (malicious_ratio * 100) + (suspicious_ratio * 50)
            
            report['risk_assessment'] = {
                'risk_score': min(risk_score, 100),
                'risk_level': self._determine_risk_level(risk_score),
                'malicious_indicators': malicious_count,
                'suspicious_indicators': suspicious_count,
                'clean_indicators': len(clean_indicators),
                'failed_lookups': len(failed_lookups)
            }
            
            # Generate recommendations
            report['recommendations'] = self._generate_threat_intel_recommendations(
                malicious_indicators, suspicious_indicators, report['risk_assessment']
            )
            
            # Summary
            report['summary'] = {
                'total_indicators': total_indicators,
                'malicious_found': malicious_count,
                'suspicious_found': suspicious_count,
                'clean_indicators': len(clean_indicators),
                'overall_risk_level': report['risk_assessment']['risk_level'],
                'primary_threats': [f['indicator_value'] for f in report['threat_findings'][:5]]
            }
            
            return report
            
        except Exception as e:
            return {
                'error': f'Failed to generate threat intelligence report: {str(e)}',
                'report_type': 'threat_intelligence',
                'generated_at': datetime.now().isoformat()
            }
    
    def generate_comprehensive_report(self, file_reports: List[Dict], network_reports: List[Dict], 
                                    threat_intel_reports: List[Dict]) -> Dict:
        """Generate comprehensive security assessment report"""
        try:
            report = {
                'report_type': 'comprehensive',
                'title': 'Comprehensive Security Assessment Report',
                'generated_at': datetime.now().isoformat(),
                'executive_summary': {},
                'detailed_findings': {
                    'file_analysis': [],
                    'network_analysis': [],
                    'threat_intelligence': []
                },
                'overall_risk_assessment': {},
                'strategic_recommendations': [],
                'action_plan': []
            }
            
            # Aggregate findings from all reports
            all_findings = []
            critical_count = 0
            high_count = 0
            medium_count = 0
            
            # Process file analysis reports
            for file_report in file_reports:
                if 'security_analysis' in file_report:
                    findings = file_report['security_analysis'].get('findings', [])
                    for finding in findings:
                        finding['source_report'] = 'File Analysis'
                        all_findings.append(finding)
                        
                        severity = finding.get('severity', 'LOW')
                        if severity == 'CRITICAL':
                            critical_count += 1
                        elif severity == 'HIGH':
                            high_count += 1
                        elif severity == 'MEDIUM':
                            medium_count += 1
                
                report['detailed_findings']['file_analysis'].append({
                    'filename': file_report.get('file_details', {}).get('filename', 'Unknown'),
                    'risk_level': file_report.get('risk_assessment', {}).get('risk_level', 'UNKNOWN'),
                    'findings_count': len(file_report.get('security_analysis', {}).get('findings', []))
                })
            
            # Process network analysis reports
            for network_report in network_reports:
                if 'anomaly_analysis' in network_report:
                    anomalies = network_report['anomaly_analysis'].get('critical_anomalies', [])
                    for anomaly in anomalies:
                        anomaly['source_report'] = 'Network Analysis'
                        all_findings.append(anomaly)
                        
                        severity = anomaly.get('severity', 'LOW')
                        if severity == 'CRITICAL':
                            critical_count += 1
                        elif severity == 'HIGH':
                            high_count += 1
                        elif severity == 'MEDIUM':
                            medium_count += 1
                
                report['detailed_findings']['network_analysis'].append({
                    'connections_analyzed': network_report.get('summary', {}).get('total_connections', 0),
                    'anomalies_detected': network_report.get('summary', {}).get('anomalies_detected', 0),
                    'risk_level': network_report.get('risk_assessment', {}).get('risk_level', 'UNKNOWN')
                })
            
            # Process threat intelligence reports
            for ti_report in threat_intel_reports:
                if 'threat_findings' in ti_report:
                    findings = ti_report['threat_findings']
                    for finding in findings:
                        finding['source_report'] = 'Threat Intelligence'
                        all_findings.append(finding)
                        
                        severity = finding.get('severity', 'LOW')
                        if severity == 'CRITICAL':
                            critical_count += 1
                        elif severity == 'HIGH':
                            high_count += 1
                        elif severity == 'MEDIUM':
                            medium_count += 1
                
                report['detailed_findings']['threat_intelligence'].append({
                    'indicators_analyzed': ti_report.get('summary', {}).get('total_indicators', 0),
                    'malicious_found': ti_report.get('summary', {}).get('malicious_found', 0),
                    'risk_level': ti_report.get('risk_assessment', {}).get('risk_level', 'UNKNOWN')
                })
            
            # Overall risk assessment
            total_findings = len(all_findings)
            overall_risk_score = 0
            
            if total_findings > 0:
                # Weight findings by severity
                overall_risk_score = (critical_count * 25) + (high_count * 15) + (medium_count * 5)
                overall_risk_score = min(overall_risk_score, 100)
            
            report['overall_risk_assessment'] = {
                'risk_score': overall_risk_score,
                'risk_level': self._determine_risk_level(overall_risk_score),
                'total_findings': total_findings,
                'critical_findings': critical_count,
                'high_findings': high_count,
                'medium_findings': medium_count,
                'security_posture': self._assess_security_posture(overall_risk_score)
            }
            
            # Strategic recommendations
            report['strategic_recommendations'] = self._generate_strategic_recommendations(
                report['overall_risk_assessment'], all_findings
            )
            
            # Action plan
            report['action_plan'] = self._generate_action_plan(all_findings, report['overall_risk_assessment'])
            
            # Executive summary
            report['executive_summary'] = {
                'assessment_period': datetime.now().strftime('%Y-%m-%d'),
                'total_security_events': total_findings,
                'critical_issues': critical_count,
                'overall_risk_level': report['overall_risk_assessment']['risk_level'],
                'security_posture': report['overall_risk_assessment']['security_posture'],
                'immediate_action_required': critical_count > 0 or high_count > 5,
                'key_recommendations': report['strategic_recommendations'][:3]
            }
            
            return report
            
        except Exception as e:
            return {
                'error': f'Failed to generate comprehensive report: {str(e)}',
                'report_type': 'comprehensive',
                'generated_at': datetime.now().isoformat()
            }
    
    def export_report_to_json(self, report: Dict) -> str:
        """Export report to JSON format"""
        try:
            return json.dumps(report, indent=2, default=str)
        except Exception as e:
            return json.dumps({'error': f'Failed to export report: {str(e)}'}, indent=2)
    
    def create_report_visualizations(self, report: Dict) -> Dict:
        """Create visualizations for the report"""
        try:
            visualizations = {}
            
            if report.get('report_type') == 'comprehensive':
                # Risk level distribution pie chart
                risk_assessment = report.get('overall_risk_assessment', {})
                
                fig_risk = go.Figure(data=[go.Pie(
                    labels=['Critical', 'High', 'Medium'],
                    values=[
                        risk_assessment.get('critical_findings', 0),
                        risk_assessment.get('high_findings', 0),
                        risk_assessment.get('medium_findings', 0)
                    ],
                    marker_colors=['#dc3545', '#fd7e14', '#ffc107']
                )])
                
                fig_risk.update_layout(title='Security Findings by Severity')
                visualizations['risk_distribution'] = fig_risk
                
                # Risk score gauge
                risk_score = risk_assessment.get('risk_score', 0)
                fig_gauge = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=risk_score,
                    domain={'x': [0, 1], 'y': [0, 1]},
                    title={'text': "Overall Risk Score"},
                    gauge={
                        'axis': {'range': [None, 100]},
                        'bar': {'color': "darkred" if risk_score > 70 else "orange" if risk_score > 40 else "green"},
                        'steps': [
                            {'range': [0, 40], 'color': "lightgray"},
                            {'range': [40, 70], 'color': "yellow"},
                            {'range': [70, 100], 'color': "red"}
                        ]
                    }
                ))
                visualizations['risk_gauge'] = fig_gauge
            
            return visualizations
            
        except Exception as e:
            st.error(f"Failed to create report visualizations: {str(e)}")
            return {}
    
    def _calculate_overall_risk(self, findings: List[Dict], file_results: Dict, ml_results: Dict) -> str:
        """Calculate overall risk level"""
        risk_score = 0
        
        # Count findings by severity
        critical = len([f for f in findings if f.get('severity') == 'CRITICAL'])
        high = len([f for f in findings if f.get('severity') == 'HIGH'])
        medium = len([f for f in findings if f.get('severity') == 'MEDIUM'])
        
        risk_score = (critical * 30) + (high * 20) + (medium * 10)
        
        return self._determine_risk_level(risk_score)
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level from score"""
        if risk_score >= 80:
            return 'CRITICAL'
        elif risk_score >= 60:
            return 'HIGH'
        elif risk_score >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_file_recommendations(self, findings: List[Dict], file_results: Dict, ml_results: Dict) -> List[str]:
        """Generate file analysis recommendations"""
        recommendations = []
        
        if any(f.get('severity') == 'CRITICAL' for f in findings):
            recommendations.append("IMMEDIATE ACTION: Do not execute this file. Quarantine immediately.")
            recommendations.append("Run additional scans with updated antivirus engines")
            recommendations.append("Submit file to security team for detailed analysis")
        
        if any(f.get('type') == 'YARA Detection' for f in findings):
            recommendations.append("File matches known malware signatures - treat as potentially malicious")
        
        if ml_results and ml_results.get('malware_probability', 0) > 0.5:
            recommendations.append("Machine learning models indicate high malware probability")
            recommendations.append("Consider behavioral analysis in isolated environment")
        
        if not recommendations:
            recommendations.append("File appears clean but continue monitoring")
            recommendations.append("Regular security scans recommended")
        
        return recommendations
    
    def _generate_network_recommendations(self, high_risk_conns: List[Dict], anomalies: Dict, risk_assessment: Dict) -> List[str]:
        """Generate network analysis recommendations"""
        recommendations = []
        
        if risk_assessment.get('risk_level') in ['CRITICAL', 'HIGH']:
            recommendations.append("IMMEDIATE ACTION: Review and potentially block high-risk connections")
            recommendations.append("Implement enhanced network monitoring")
        
        if anomalies.get('critical_anomalies'):
            recommendations.append("Investigate critical network anomalies immediately")
            recommendations.append("Consider implementing additional network segmentation")
        
        if len(high_risk_conns) > 0:
            recommendations.append(f"Review {len(high_risk_conns)} high-risk network connections")
            recommendations.append("Update firewall rules to block suspicious IPs")
        
        if not recommendations:
            recommendations.append("Network activity appears normal")
            recommendations.append("Continue regular monitoring")
        
        return recommendations
    
    def _generate_threat_intel_recommendations(self, malicious: List[Dict], suspicious: List[Dict], risk_assessment: Dict) -> List[str]:
        """Generate threat intelligence recommendations"""
        recommendations = []
        
        if len(malicious) > 0:
            recommendations.append("CRITICAL: Block all confirmed malicious indicators immediately")
            recommendations.append("Update security controls with new threat indicators")
        
        if len(suspicious) > 0:
            recommendations.append("Monitor suspicious indicators closely")
            recommendations.append("Consider adding suspicious indicators to watch lists")
        
        if risk_assessment.get('risk_level') in ['CRITICAL', 'HIGH']:
            recommendations.append("Enhance threat intelligence feeds")
            recommendations.append("Implement automated threat indicator blocking")
        
        if not recommendations:
            recommendations.append("No immediate threats detected")
            recommendations.append("Continue regular threat intelligence monitoring")
        
        return recommendations
    
    def _generate_strategic_recommendations(self, risk_assessment: Dict, all_findings: List[Dict]) -> List[str]:
        """Generate strategic recommendations for comprehensive report"""
        recommendations = []
        
        risk_level = risk_assessment.get('risk_level', 'LOW')
        critical_count = risk_assessment.get('critical_findings', 0)
        
        if risk_level == 'CRITICAL':
            recommendations.append("Implement emergency security response procedures")
            recommendations.append("Conduct immediate security audit across all systems")
            recommendations.append("Consider engaging external security experts")
        elif risk_level == 'HIGH':
            recommendations.append("Prioritize security remediation efforts")
            recommendations.append("Increase security monitoring and alerting")
            recommendations.append("Review and update security policies")
        elif risk_level == 'MEDIUM':
            recommendations.append("Address identified security gaps systematically")
            recommendations.append("Enhance security awareness training")
            recommendations.append("Regular security assessments recommended")
        else:
            recommendations.append("Maintain current security posture")
            recommendations.append("Continue regular security monitoring")
        
        # Add specific recommendations based on finding types
        source_reports = set(f.get('source_report', '') for f in all_findings)
        
        if 'File Analysis' in source_reports:
            recommendations.append("Strengthen endpoint protection and file scanning")
        
        if 'Network Analysis' in source_reports:
            recommendations.append("Enhance network security monitoring capabilities")
        
        if 'Threat Intelligence' in source_reports:
            recommendations.append("Improve threat intelligence integration and response")
        
        return recommendations[:6]  # Limit to top 6 recommendations
    
    def _generate_action_plan(self, all_findings: List[Dict], risk_assessment: Dict) -> List[Dict]:
        """Generate action plan with priorities and timelines"""
        action_items = []
        
        # Critical actions (immediate)
        critical_findings = [f for f in all_findings if f.get('severity') == 'CRITICAL']
        if critical_findings:
            action_items.append({
                'priority': 'IMMEDIATE',
                'timeline': '0-24 hours',
                'action': 'Address all critical security findings',
                'details': f"{len(critical_findings)} critical issues require immediate attention",
                'owner': 'Security Team Lead'
            })
        
        # High priority actions (short term)
        high_findings = [f for f in all_findings if f.get('severity') == 'HIGH']
        if high_findings:
            action_items.append({
                'priority': 'HIGH',
                'timeline': '1-7 days',
                'action': 'Resolve high-severity security issues',
                'details': f"{len(high_findings)} high-priority issues identified",
                'owner': 'Security Team'
            })
        
        # Medium priority actions (medium term)
        medium_findings = [f for f in all_findings if f.get('severity') == 'MEDIUM']
        if medium_findings:
            action_items.append({
                'priority': 'MEDIUM',
                'timeline': '1-4 weeks',
                'action': 'Address medium-priority security concerns',
                'details': f"{len(medium_findings)} medium-priority issues to resolve",
                'owner': 'IT Security'
            })
        
        # Long term improvements
        action_items.append({
            'priority': 'LOW',
            'timeline': '1-3 months',
            'action': 'Enhance overall security posture',
            'details': 'Implement strategic security improvements',
            'owner': 'CISO/Security Leadership'
        })
        
        return action_items
    
    def _assess_security_posture(self, risk_score: float) -> str:
        """Assess overall security posture"""
        if risk_score >= 80:
            return 'POOR - Immediate action required'
        elif risk_score >= 60:
            return 'WEAK - Significant improvements needed'
        elif risk_score >= 40:
            return 'MODERATE - Some improvements recommended'
        elif risk_score >= 20:
            return 'GOOD - Minor enhancements suggested'
        else:
            return 'EXCELLENT - Strong security posture'
    
    def _format_anomaly_description(self, anomaly: Dict) -> str:
        """Format anomaly description for reports"""
        anomaly_type = anomaly.get('type', 'Unknown')
        
        if anomaly_type == 'port_scan':
            return f"Port scanning detected from {anomaly.get('remote_ip', 'unknown IP')} - {anomaly.get('port_count', 0)} ports scanned"
        elif anomaly_type == 'high_frequency':
            return f"High frequency connections detected - {anomaly.get('connection_count', 0)} connections in short time window"
        elif anomaly_type == 'high_outbound_data':
            return f"Unusual outbound data transfer - {anomaly.get('bytes_sent', 0)} bytes sent"
        elif anomaly_type == 'suspicious_geolocation':
            return f"Connections to suspicious locations - {anomaly.get('count', 0)} connections"
        else:
            return f"Network anomaly detected: {anomaly_type}"
    
    def _get_network_recommended_action(self, risk_score: float) -> str:
        """Get recommended action based on network risk score"""
        if risk_score >= 80:
            return "CRITICAL: Isolate affected systems and investigate immediately"
        elif risk_score >= 60:
            return "HIGH: Block suspicious connections and enhance monitoring"
        elif risk_score >= 40:
            return "MEDIUM: Review network policies and investigate anomalies"
        else:
            return "LOW: Continue normal monitoring"
    
    def _generate_risk_assessment(self, findings: List[Dict], file_results: Dict, ml_results: Dict) -> Dict:
        """Generate detailed risk assessment"""
        risk_factors = []
        risk_score = 0
        
        # Analyze findings
        critical_count = len([f for f in findings if f.get('severity') == 'CRITICAL'])
        high_count = len([f for f in findings if f.get('severity') == 'HIGH'])
        medium_count = len([f for f in findings if f.get('severity') == 'MEDIUM'])
        
        risk_score = (critical_count * 30) + (high_count * 20) + (medium_count * 10)
        
        if critical_count > 0:
            risk_factors.append(f"{critical_count} critical security issues detected")
        if high_count > 0:
            risk_factors.append(f"{high_count} high-severity issues identified")
        if medium_count > 0:
            risk_factors.append(f"{medium_count} medium-severity concerns found")
        
        # ML analysis risk factors
        if ml_results and not ml_results.get('error'):
            malware_prob = ml_results.get('malware_probability', 0)
            if malware_prob > 0.7:
                risk_factors.append(f"High malware probability ({malware_prob:.1%})")
            elif malware_prob > 0.4:
                risk_factors.append(f"Moderate malware probability ({malware_prob:.1%})")
        
        risk_level = self._determine_risk_level(risk_score)
        
        return {
            'risk_score': min(risk_score, 100),
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'recommended_action': self._get_recommended_action(risk_level),
            'confidence': 'HIGH' if len(findings) > 0 else 'MEDIUM'
        }
    
    def _get_recommended_action(self, risk_level: str) -> str:
        """Get recommended action based on risk level"""
        actions = {
            'CRITICAL': 'IMMEDIATE ACTION REQUIRED - Do not execute file, quarantine immediately',
            'HIGH': 'HIGH PRIORITY - Detailed investigation required before use',
            'MEDIUM': 'CAUTION - Additional verification recommended',
            'LOW': 'File appears safe but continue monitoring'
        }
        return actions.get(risk_level, 'Continue standard security procedures')
