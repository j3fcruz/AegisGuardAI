# utils/ui_helpers.py
import streamlit as st
import asyncio
from .file_analyzer import FileAnalyzer
from .ml_detector import MLThreatDetector
from .network_analyzer import NetworkAnalyzer
from .threat_intelligence import ThreatIntelligence
from .report_generator import ReportGenerator
from .ip_analyzer import IPAnalyzer

@st.cache_resource
def init_analyzers():
    """Initialize analyzer classes with caching for performance"""
    try:
        file_analyzer = FileAnalyzer()
        ml_detector = MLThreatDetector()
        network_analyzer = NetworkAnalyzer()
        threat_intel = ThreatIntelligence()
        report_generator = ReportGenerator()
        ip_analyzer = IPAnalyzer()

        return {
            'file_analyzer': file_analyzer,
            'ml_detector': ml_detector,
            'network_analyzer': network_analyzer,
            'threat_intel': threat_intel,
            'report_generator': report_generator,
            'ip_analyzer': ip_analyzer
        }
    except Exception as e:
        st.error(f"Failed to initialize analyzers: {str(e)}")
        return None

def run_async(coro):
    """
    Safely run async coroutine in Streamlit.
    Uses existing event loop if present, or starts a new one in a thread.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If event loop is already running (Streamlit), run in a new thread
            future = asyncio.run_coroutine_threadsafe(coro, loop)
            return future.result()
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        # No event loop, create a new one
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
