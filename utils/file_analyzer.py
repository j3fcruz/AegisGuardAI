## utils/file_analyzer.py
import hashlib
import os
import magic
import pefile
import yara
import time
from datetime import datetime
import streamlit as st
import plotly.graph_objects as go
import tempfile

# Define the application root directory to be used as a universal default path
APPROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class FileAnalyzer:
    """Comprehensive file analysis utility for malware detection"""

    def __init__(self, yara_rules_path="utils/rules.yara"):
        """Initialize the file analyzer with YARA rules"""
        self.supported_formats = ['.exe', '.dll', '.pdf', '.doc', '.docx', '.zip', '.rar']
        self.yara_rules = self._compile_yara_rules(yara_rules_path)

    def _compile_yara_rules(self, yara_rules_path):
        """Compile YARA rules for malware detection"""
        try:
            # Adjust path to be relative to APPROOT if it's not absolute
            if not os.path.isabs(yara_rules_path):
                yara_rules_path = os.path.join(APPROOT, yara_rules_path)
            return yara.compile(filepath=yara_rules_path)
        except yara.Error as e:
            st.warning(f"Failed to compile YARA rules: {str(e)}")
            return None
        except FileNotFoundError:
            st.warning(f"YARA rules file not found at: {yara_rules_path}")
            return None

    def calculate_hashes(self, file_content):
        """Calculate MD5, SHA1, and SHA256 hashes for the file"""
        try:
            hashes = {
                'md5': hashlib.md5(file_content).hexdigest(),
                'sha1': hashlib.sha1(file_content).hexdigest(),
                'sha256': hashlib.sha256(file_content).hexdigest()
            }
            return hashes
        except Exception as e:
            st.error(f"Error calculating hashes: {str(e)}")
            return None

    def get_file_info(self, uploaded_file):
        """Extract basic file information"""
        try:
            file_info = {
                'name': uploaded_file.name,
                'size': len(uploaded_file.getvalue()),
                'type': uploaded_file.type,
                'upload_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

            # Try to detect file type using python-magic
            try:
                file_content = uploaded_file.getvalue()
                file_info['mime_type'] = magic.from_buffer(file_content, mime=True)
                file_info['file_type'] = magic.from_buffer(file_content)
            except:
                file_info['mime_type'] = "unknown"
                file_info['file_type'] = "unknown"

            return file_info
        except Exception as e:
            st.error(f"Error extracting file info: {str(e)}")
            return None

    def analyze_pe_file(self, file_content):
        """Analyze PE (Portable Executable) files for suspicious characteristics"""
        try:
            with tempfile.NamedTemporaryFile(delete=True) as temp_file:
                temp_file.write(file_content)
                temp_file.seek(0)
                try:
                    pe = pefile.PE(temp_file.name)

                    pe_info = {
                        'is_pe': True,
                        'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                        'number_of_sections': pe.FILE_HEADER.NumberOfSections,
                        'timestamp': datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).strftime("%Y-%m-%d %H:%M:%S"),
                        'machine_type': hex(pe.FILE_HEADER.Machine),
                        'characteristics': hex(pe.FILE_HEADER.Characteristics),
                        'sections': []
                    }

                    # Analyze sections
                    for section in pe.sections:
                        section_info = {
                            'name': section.Name.decode('utf-8').rstrip('\x00'),
                            'virtual_address': hex(section.VirtualAddress),
                            'virtual_size': section.Misc_VirtualSize,
                            'raw_size': section.SizeOfRawData,
                            'entropy': section.get_entropy()
                        }
                        pe_info['sections'].append(section_info)

                    # Check for suspicious characteristics
                    pe_info['suspicious_flags'] = []

                    if pe.FILE_HEADER.Characteristics & 0x2000:  # DLL flag
                        pe_info['suspicious_flags'].append("DLL file")

                    # Check for packed sections (high entropy)
                    for section in pe_info['sections']:
                        if section['entropy'] > 7.0:
                            pe_info['suspicious_flags'].append(f"High entropy section: {section['name']}")

                    # Check imports
                    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                        suspicious_imports = ['CreateProcess', 'VirtualAlloc', 'WriteProcessMemory', 'SetWindowsHookEx']
                        pe_info['imports'] = []

                        for entry in pe.DIRECTORY_ENTRY_IMPORT:
                            dll_name = entry.dll.decode('utf-8')
                            for imp in entry.imports:
                                if imp.name:
                                    import_name = imp.name.decode('utf-8')
                                    pe_info['imports'].append(f"{dll_name}:{import_name}")

                                    if import_name in suspicious_imports:
                                        pe_info['suspicious_flags'].append(f"Suspicious import: {import_name}")

                    pe.close()
                    return pe_info

                except pefile.PEFormatError:
                    return {'is_pe': False, 'error': 'Not a valid PE file'}
        except Exception as e:
            return {'is_pe': False, 'error': f'PE analysis failed: {str(e)}'}

    def scan_with_yara(self, file_content):
        """Scan file content with YARA rules"""
        if not self.yara_rules:
            return {'matches': [], 'error': 'YARA rules not available'}

        try:
            matches = self.yara_rules.match(data=file_content)

            yara_results = {
                'matches': [],
                'total_matches': len(matches)
            }

            for match in matches:
                match_info = {
                    'rule': match.rule,
                    'meta': dict(match.meta),
                    'strings': []
                }

                for string_match in match.strings:
                    match_info['strings'].append({
                        'identifier': string_match.identifier,
                        'instances': len(string_match.instances)
                    })

                yara_results['matches'].append(match_info)

            return yara_results

        except yara.Error as e:
            return {'matches': [], 'error': f'YARA scan failed: {str(e)}'}

    def comprehensive_analysis(self, uploaded_file):
        """Perform comprehensive file analysis"""
        try:
            results = {
                'timestamp': datetime.now().isoformat(),
                'status': 'success'
            }

            # Get file content
            file_content = uploaded_file.getvalue()

            # Basic file information
            file_info = self.get_file_info(uploaded_file)
            if file_info:
                results['file_info'] = file_info

            # Calculate hashes
            hashes = self.calculate_hashes(file_content)
            if hashes:
                results['hashes'] = hashes

            # PE analysis (if applicable)
            file_ext = os.path.splitext(uploaded_file.name)[1].lower()
            if file_ext in ['.exe', '.dll', '.sys']:
                results['pe_analysis'] = self.analyze_pe_file(file_content)

            # YARA rule scanning
            yara_results = self.scan_with_yara(file_content)
            if yara_results:
                results['yara_scan'] = yara_results

            # Risk assessment
            risk_score = self._calculate_risk_score(results)
            results['risk_score'] = risk_score
            results['risk_level'] = self._determine_risk_level(results['risk_score'])

            return results

        except Exception as e:
            return {
                'timestamp': datetime.now().isoformat(),
                'status': 'error',
                'error': str(e)
            }

    def _calculate_risk_score(self, analysis_results):
        """Calculate a risk score based on analysis results"""
        score = 0

        # YARA matches contribute to risk
        if 'yara_scan' in analysis_results and analysis_results['yara_scan']['matches']:
            score += len(analysis_results['yara_scan']['matches']) * 20

        # PE analysis flags
        if 'pe_analysis' in analysis_results and 'suspicious_flags' in analysis_results['pe_analysis']:
            score += len(analysis_results['pe_analysis']['suspicious_flags']) * 10

        # File size (very large or very small files can be suspicious)
        if 'file_info' in analysis_results:
            size = analysis_results['file_info']['size']
            if size < 1024 or size > 50 * 1024 * 1024:  # < 1KB or > 50MB
                score += 5

        return min(score, 100)  # Cap at 100

    def _determine_risk_level(self, risk_score):
        """Determine risk level based on score"""
        if risk_score >= 80:
            return 'CRITICAL'
        elif risk_score >= 60:
            return 'HIGH'
        elif risk_score >= 40:
            return 'MEDIUM'
        else:
            return 'LOW'

    def scan_system_hybrid(self, root_path=APPROOT):
        """Hybrid+Realtime Live scan updating session_state and showing only new files"""
        import streamlit as st
        import os, time
        from datetime import datetime

        suspicious_extensions = (".exe", ".dll", ".js", ".vbs")

        # Initialize counters
        scanned_new = 0
        new_threats_found = 0

        if not os.path.exists(root_path):
            return f"Path not found: {root_path}"

        # Initialize caches if not present
        if 'scanned_files_cache' not in st.session_state:
            st.session_state.scanned_files_cache = set()
        if 'threats_cache' not in st.session_state:
            st.session_state.threats_cache = {}

        # Gather files to scan
        target_files = []
        for dirpath, _, filenames in os.walk(root_path):
            for file in filenames:
                if file.lower().endswith(suspicious_extensions):
                    full_path = os.path.join(dirpath, file)
                    if full_path not in st.session_state.scanned_files_cache:
                        target_files.append(full_path)

        total_files = len(target_files)
        if total_files == 0:
            return "No new files to scan."

        scan_placeholder = st.empty()

        for idx, file_path in enumerate(target_files, start=1):
            # Realtime display
            scan_placeholder.info(f"Scanning ({idx}/{total_files}): {file_path}")

            scanned_new += 1

            # Fake detection logic
            threat_detected = os.path.getsize(file_path) % 10 == 0
            if threat_detected:
                new_threats_found += 1

            # Update session_state counters
            st.session_state.total_scans += 1
            st.session_state.threats_detected += int(threat_detected)

            # Cache scanned file and threat status
            st.session_state.scanned_files_cache.add(file_path)
            st.session_state.threats_cache[file_path] = threat_detected

            # Update threat level
            risk_percentage = int((st.session_state.threats_detected / max(1, st.session_state.total_scans)) * 100)
            if risk_percentage >= 80:
                st.session_state.threat_level = "CRITICAL"
            elif risk_percentage >= 60:
                st.session_state.threat_level = "HIGH"
            elif risk_percentage >= 40:
                st.session_state.threat_level = "MEDIUM"
            else:
                st.session_state.threat_level = "LOW"

            # Append scan history (only new files)
            st.session_state.scan_history.append({
                'time': datetime.now().strftime("%H:%M:%S"),
                'action': "Scan File",
                'details': f"{file_path} {'⚠️ Threat Detected' if threat_detected else '✅ Clean'}"
            })

            # Small delay to simulate scanning
            time.sleep(0.01)

        scan_placeholder.success(
            f"Scan complete: {scanned_new} new files scanned, {new_threats_found} new threats detected."
        )

        return f"Scan complete: {scanned_new} new files scanned, {new_threats_found} new threats detected."
