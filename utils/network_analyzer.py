# utils/network_analyzer.py

import re
import json
import socket
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Union, Optional
import os

import numpy as np
import pandas as pd
import requests
import streamlit as st


class NetworkAnalyzer:
    """
    Network traffic analysis and anomaly detection.
    Provides connection parsing, enrichment, anomaly detection,
    and summary generation.
    """

    def __init__(self, virustotal_api_key: Optional[str] = None, malicious_ports: Optional[set] = None, suspicious_protocols: Optional[set] = None):
        self.connection_history: List[Dict] = []
        self.baseline_stats: Dict = {}
        self.baseline_established: bool = False
        self.virustotal_api_key = virustotal_api_key or os.environ.get("VIRUSTOTAL_API_KEY")

        self.MALICIOUS_PORTS = malicious_ports or {
            1337, 31337, 12345, 54321, 9999, 40421, 40422, 40423, 40426,
            6666, 6667, 6670, 2801, 4590, 16959, 65506
        }

        self.SUSPICIOUS_PROTOCOLS = suspicious_protocols or {'IRC', 'TORRENT', 'P2P'}

        self.COMMON_SERVICE_PORTS = {
            80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 25: 'SMTP', 110: 'POP3',
            143: 'IMAP', 993: 'IMAPS', 995: 'POP3S', 21: 'FTP', 22: 'SSH',
            23: 'TELNET', 3389: 'RDP'
        }

    # ------------------------------
    # Parsing Network Logs
    # ------------------------------
    def parse_network_log(
        self, log_data: Union[str, list, dict]
    ) -> List[Dict]:
        """Parse network log data from string, list, or JSON dict"""
        try:
            if isinstance(log_data, str):
                connections = self._parse_text_log(log_data)
            elif isinstance(log_data, list):
                connections = log_data
            elif isinstance(log_data, dict):
                connections = log_data.get("connections", [])
            else:
                connections = []

            return self._enrich_connections(connections)

        except Exception as e:
            st.error(f"Network log parsing error: {e}")
            return []

    def _parse_text_log(self, log_text: str) -> List[Dict]:
        """Parse text-based network logs line by line"""
        connections = []
        for line in log_text.strip().splitlines():
            if line := line.strip():
                if conn := self._parse_log_line(line):
                    connections.append(conn)
        return connections

    def _parse_log_line(self, line: str) -> Optional[Dict]:
        """Parse an individual log line with multiple patterns"""
        patterns = [
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) .* (\d+\.\d+\.\d+\.\d+):(\d+) .* (\d+\.\d+\.\d+\.\d+):(\d+) .* (\w+)',
            r'(\d+\.\d+\.\d+\.\d+):(\d+) -> (\d+\.\d+\.\d+\.\d+):(\d+) (\w+) (\d+) bytes',
            r'(\d+\.\d+\.\d+\.\d+) (\d+) (\d+\.\d+\.\d+\.\d+) (\d+) (\w+)'
        ]
        for pattern in patterns:
            if match := re.search(pattern, line):
                return self._create_connection_object(match.groups())
        return None

    def _create_connection_object(self, parsed: tuple) -> Optional[Dict]:
        """Convert regex groups into structured connection dict"""
        try:
            if len(parsed) >= 6:
                return {
                    "timestamp": parsed[0],
                    "local_ip": parsed[1],
                    "local_port": int(parsed[2]),
                    "remote_ip": parsed[3],
                    "remote_port": int(parsed[4]),
                    "protocol": parsed[5].upper(),
                    "bytes_sent": np.random.randint(100, 10000),
                    "bytes_recv": np.random.randint(100, 10000),
                    "duration": np.random.uniform(0.1, 30.0),
                }
            else:
                return {
                    "timestamp": datetime.now().isoformat(),
                    "local_ip": parsed[0],
                    "local_port": int(parsed[1]) if parsed[1].isdigit() else 0,
                    "remote_ip": parsed[2],
                    "remote_port": int(parsed[3]) if parsed[3].isdigit() else 0,
                    "protocol": parsed[4].upper() if len(parsed) > 4 else "TCP",
                    "bytes_sent": np.random.randint(100, 10000),
                    "bytes_recv": np.random.randint(100, 10000),
                    "duration": np.random.uniform(0.1, 30.0),
                }
        except Exception:
            return None

    # ------------------------------
    # Data Enrichment
    # ------------------------------
    def _enrich_connections(self, connections: List[Dict]) -> List[Dict]:
        enriched = []
        for conn in connections:
            try:
                conn["remote_country"] = self._get_country_from_ip(conn.get("remote_ip", ""))
                conn["risk_score"] = self._calculate_risk(conn)
                conn["protocol_class"] = self._classify_protocol(conn)
                conn["is_during_business_hours"] = self._is_business_hours(conn.get("timestamp"))
                conn["virustotal"] = self._check_ip_virustotal(conn.get("remote_ip"))
                enriched.append(conn)
            except Exception as e:
                st.warning(f"Error enriching connection: {e}")
        return enriched

    def _get_country_from_ip(self, ip: str) -> str:
        """
        Simple IP-to-country mapping.
        NOTE: This is a simplistic implementation for demonstration purposes.
        For enterprise-grade applications, use a dedicated geolocation database
        or API like MaxMind GeoIP2.
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return "Private/Local"
            elif ip_obj.is_loopback:
                return "Loopback"

            first_octet = int(ip.split(".")[0])
            if first_octet < 64:
                return "US"
            elif first_octet < 128:
                return "EU"
            elif first_octet < 192:
                return "ASIA"
            else:
                return "OTHER"
        except Exception:
            return "Unknown"

    def _calculate_risk(self, conn: Dict) -> int:
        """Compute a numeric risk score for a connection"""
        risk = 0
        port = conn.get("remote_port", 0)
        protocol = conn.get("protocol", "").upper()
        bytes_total = conn.get("bytes_sent", 0) + conn.get("bytes_recv", 0)

        if port in self.MALICIOUS_PORTS:
            risk += 50
        if port > 49152:
            risk += 10
        try:
            if ipaddress.ip_address(conn.get("remote_ip", "")).is_private:
                risk += 5
        except Exception:
            pass
        if bytes_total > 1_000_000:
            risk += 15
        if conn.get("duration", 0) > 300:
            risk += 10
        if protocol in self.SUSPICIOUS_PROTOCOLS:
            risk += 20

        return min(risk, 100)

    def _classify_protocol(self, conn: Dict) -> str:
        """Classify protocol/service based on port"""
        port = conn.get("remote_port", 0)
        if port in self.COMMON_SERVICE_PORTS:
            return self.COMMON_SERVICE_PORTS[port]
        elif port < 1024:
            return "SYSTEM"
        elif port < 49152:
            return "REGISTERED"
        return "DYNAMIC"

    def _is_business_hours(self, timestamp_str: str) -> bool:
        """Return True if timestamp is during business hours"""
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            return timestamp.weekday() < 5 and 8 <= timestamp.hour <= 18
        except Exception:
            return True

    # ------------------------------
    # Anomaly Detection
    # ------------------------------
    def detect_anomalies(self, connections: List[Dict]) -> Dict:
        """
        Detect anomalies using statistics, patterns, and behavior.
        NOTE: This is a batch analysis implementation. For real-time analysis,
        consider using a streaming approach with libraries like Scapy.
        """
        if not connections:
            return {"anomalies": [], "summary": "No connections to analyze"}

        anomalies = []
        df = pd.DataFrame(connections)
        numeric_cols = ["bytes_sent", "bytes_recv", "duration", "remote_port", "risk_score"]

        # IQR statistical anomalies
        for col in numeric_cols:
            if col in df.columns:
                Q1, Q3 = df[col].quantile([0.25, 0.75])
                IQR = Q3 - Q1
                lower, upper = Q1 - 1.5 * IQR, Q3 + 1.5 * IQR
                for _, row in df[(df[col] < lower) | (df[col] > upper)].iterrows():
                    anomalies.append({
                        "type": f"{col}_outlier",
                        "connection": row.to_dict(),
                        "value": row[col],
                        "bounds": [lower, upper],
                        "severity": "HIGH" if row["risk_score"] > 50 else "MEDIUM",
                    })

        anomalies.extend(self._pattern_anomalies(connections))
        anomalies.extend(self._behavioral_anomalies(df))

        return {
            "anomalies": anomalies,
            "total_connections": len(connections),
            "anomaly_count": len(anomalies),
            "anomaly_percentage": len(anomalies) / len(connections) * 100,
            "summary": f"Found {len(anomalies)} anomalies in {len(connections)} connections",
        }

    def _pattern_anomalies(self, connections: List[Dict]) -> List[Dict]:
        """Detect port scans and high-frequency connections"""
        anomalies = []
        ip_groups = defaultdict(list)
        for conn in connections:
            ip_groups[conn.get("remote_ip", "unknown")].append(conn)

        # Port scan detection
        for ip, conns in ip_groups.items():
            if len({c.get("remote_port") for c in conns}) > 10:
                anomalies.append({
                    "type": "port_scan",
                    "remote_ip": ip,
                    "port_count": len({c.get("remote_port") for c in conns}),
                    "connection_count": len(conns),
                    "severity": "HIGH"
                })

        # High-frequency detection
        window_counts = defaultdict(int)
        for conn in connections:
            try:
                ts = datetime.fromisoformat(conn.get("timestamp", datetime.now().isoformat()))
                window = ts.replace(minute=(ts.minute // 5) * 5, second=0, microsecond=0)
                window_counts[window] += 1
            except Exception:
                continue

        for window, count in window_counts.items():
            if count > 50:
                anomalies.append({
                    "type": "high_frequency",
                    "time_window": window.isoformat(),
                    "connection_count": count,
                    "severity": "MEDIUM"
                })

        return anomalies

    def _behavioral_anomalies(self, df: pd.DataFrame) -> List[Dict]:
        """Detect behavioral anomalies like data exfiltration or suspicious geolocation"""
        anomalies = []

        if not df.empty:
            # High outbound traffic
            if {"bytes_sent", "bytes_recv"}.issubset(df.columns):
                high_outbound = df[df["bytes_sent"] > df["bytes_sent"].quantile(0.95)]
                for _, row in high_outbound.iterrows():
                    if row["bytes_sent"] > 1_000_000:
                        anomalies.append({
                            "type": "high_outbound_data",
                            "connection": row.to_dict(),
                            "bytes_sent": row["bytes_sent"],
                            "severity": "HIGH"
                        })

            # Suspicious geolocation
            if "remote_country" in df.columns:
                suspicious = df[df["remote_country"].isin({"Unknown", "OTHER"})]
                if not suspicious.empty:
                    anomalies.append({
                        "type": "suspicious_geolocation",
                        "count": len(suspicious),
                        "countries": suspicious["remote_country"].value_counts().to_dict(),
                        "severity": "MEDIUM"
                    })

        return anomalies

    # ------------------------------
    # Summary Generation
    # ------------------------------
    def generate_network_summary(self, connections: List[Dict]) -> Dict:
        """Generate a comprehensive network activity summary"""
        if not connections:
            return {"error": "No connections to analyze"}

        try:
            df = pd.DataFrame(connections)
            summary = {
                "analysis_timestamp": datetime.now().isoformat(),
                "total_connections": len(connections),
                "unique_remote_ips": df["remote_ip"].nunique() if "remote_ip" in df.columns else 0,
                "unique_ports": df["remote_port"].nunique() if "remote_port" in df.columns else 0,
                "protocol_distribution": df["protocol"].value_counts().to_dict() if "protocol" in df.columns else {},
                "top_remote_ips": df["remote_ip"].value_counts().head(10).to_dict() if "remote_ip" in df.columns else {},
                "top_ports": df["remote_port"].value_counts().head(10).to_dict() if "remote_port" in df.columns else {},
                "risk_distribution": self._risk_distribution(df),
                "data_transfer": self._data_transfer(df),
                "time_analysis": self._time_analysis(df)
            }
            return summary
        except Exception as e:
            return {"error": f"Summary generation failed: {e}"}

    def _risk_distribution(self, df: pd.DataFrame) -> Dict:
        if "risk_score" not in df.columns:
            return {}
        return {
            "low_risk": int((df["risk_score"] < 30).sum()),
            "medium_risk": int(((df["risk_score"] >= 30) & (df["risk_score"] < 70)).sum()),
            "high_risk": int((df["risk_score"] >= 70).sum()),
            "average_risk": float(df["risk_score"].mean())
        }

    def _data_transfer(self, df: pd.DataFrame) -> Dict:
        if {"bytes_sent", "bytes_recv"}.issubset(df.columns):
            return {
                "total_bytes_sent": int(df["bytes_sent"].sum()),
                "total_bytes_recv": int(df["bytes_recv"].sum()),
                "avg_bytes_sent": float(df["bytes_sent"].mean()),
                "avg_bytes_recv": float(df["bytes_recv"].mean()),
                "largest_transfer": int(max(df["bytes_sent"].max(), df["bytes_recv"].max()))
            }
        return {}

    def _time_analysis(self, df: pd.DataFrame) -> Dict:
        if "timestamp" not in df.columns:
            return {}
        try:
            df["hour"] = pd.to_datetime(df["timestamp"]).dt.hour
            return {
                "hourly_distribution": df["hour"].value_counts().sort_index().to_dict(),
                "business_hours_connections": int(df[df.get("is_during_business_hours", pd.Series([False]*len(df)))].shape[0]),
                "after_hours_connections": int(df[~df.get("is_during_business_hours", pd.Series([True]*len(df)))].shape[0])
            }
        except Exception:
            return {"error": "Could not parse timestamps"}

    # ------------------------------
    # VirusTotal Integration
    # ------------------------------
    def _check_ip_virustotal(self, ip: str) -> Dict:
        """Check IP reputation with VirusTotal, returns dummy if no API key"""
        if not self.virustotal_api_key:
            return {"ip": ip, "info": "VT check skipped (no API key)"}

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self.virustotal_api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "ip": ip,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "last_analysis_date": data.get("last_analysis_date")
                }
            return {"ip": ip, "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"ip": ip, "error": str(e)}

    # ------------------------------
    # Sample Data Generation
    # ------------------------------
    def create_sample_network_data(self, num_connections: int = 100) -> List[Dict]:
        """Generate sample network data for demonstration purposes"""
        local_ips = ['192.168.1.100', '192.168.1.101', '10.0.0.50']
        common_remote_ips = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
        suspicious_remote_ips = ['103.224.182.251', '185.220.101.32']

        connections = []
        for _ in range(num_connections):
            is_suspicious = np.random.rand() < 0.1
            remote_ip = np.random.choice(common_remote_ips + suspicious_remote_ips + [
                f"{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}"
            ])
            remote_port = np.random.choice([1337, 31337, 12345, 54321] if is_suspicious else list(range(1024, 65535)))
            bytes_sent = np.random.randint(10_000, 1_000_000) if is_suspicious else np.random.randint(100, 50_000)

            conn = {
                "timestamp": (datetime.now() - timedelta(hours=np.random.randint(0, 24))).isoformat(),
                "local_ip": np.random.choice(local_ips),
                "local_port": np.random.randint(1024, 65535),
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "protocol": np.random.choice(["TCP", "UDP", "ICMP"]),
                "bytes_sent": bytes_sent,
                "bytes_recv": np.random.randint(100, 100_000),
                "duration": np.random.uniform(0.1, 300.0),
                "packets_sent": np.random.randint(1, 1000),
                "packets_recv": np.random.randint(1, 1000)
            }
            connections.append(conn)

        return self._enrich_connections(connections)
