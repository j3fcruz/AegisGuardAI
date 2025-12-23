# utils/ml_detector.py
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import pickle
import os
import streamlit as st
import time
from datetime import datetime

class MLThreatDetector:
    """Machine Learning-based threat detection system"""
    
    def __init__(self, model_path='data/models/malware_features.pkl'):
        """Initialize ML models for threat detection"""
        self.models = {}
        self.scalers = {}
        self.feature_names = []
        self.model_path = model_path
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained models from disk"""
        try:
            if not os.path.exists(self.model_path):
                st.warning(f"Model file not found at {self.model_path}. Please run the training script.")
                self._create_default_models()
                return

            with open(self.model_path, 'rb') as f:
                model_data = pickle.load(f)

            self.models = model_data['models']
            self.scalers = model_data['scalers']
            self.feature_names = model_data['feature_names']

            msg = st.empty()
            msg.success("✅ Pre-trained ML models loaded successfully!")
            time.sleep(5)
            msg.empty()

        except Exception as e:
            msg = st.empty()
            msg.error(f"❌ Failed to load models: {str(e)}")
            time.sleep(5)
            msg.empty()
            self._create_default_models()
    
    def _create_default_models(self):
        """Create basic default models if loading fails"""
        self.models['malware_classifier'] = RandomForestClassifier(random_state=42)
        self.models['anomaly_detector'] = IsolationForest(random_state=42)
        self.scalers['malware'] = StandardScaler()
        self.feature_names = [
            'file_size', 'entropy', 'num_sections', 'suspicious_imports',
            'yara_matches', 'pe_suspicious_flags', 'feature_7', 'feature_8', 'feature_9'
        ]
    
    def extract_ml_features(self, analysis_results):
        """Extract ML features from file analysis results"""
        try:
            features = {}
            
            if 'file_info' in analysis_results:
                features['file_size'] = analysis_results['file_info']['size']
            else:
                features['file_size'] = 0
            
            if 'pe_analysis' in analysis_results and 'sections' in analysis_results['pe_analysis']:
                entropies = [section.get('entropy', 0) for section in analysis_results['pe_analysis']['sections']]
                features['entropy'] = np.mean(entropies) if entropies else 0
                features['num_sections'] = len(analysis_results['pe_analysis']['sections'])
            else:
                features['entropy'] = 0
                features['num_sections'] = 0
            
            if 'pe_analysis' in analysis_results and 'suspicious_flags' in analysis_results['pe_analysis']:
                features['pe_suspicious_flags'] = len(analysis_results['pe_analysis']['suspicious_flags'])
            else:
                features['pe_suspicious_flags'] = 0
            
            suspicious_import_keywords = ['CreateProcess', 'VirtualAlloc', 'WriteProcessMemory', 'SetWindowsHookEx']
            features['suspicious_imports'] = 0
            if 'pe_analysis' in analysis_results and 'imports' in analysis_results['pe_analysis']:
                for imp in analysis_results['pe_analysis']['imports']:
                    if any(keyword in imp for keyword in suspicious_import_keywords):
                        features['suspicious_imports'] += 1
            
            if 'yara_scan' in analysis_results:
                features['yara_matches'] = analysis_results['yara_scan'].get('total_matches', 0)
            else:
                features['yara_matches'] = 0
            
            features['feature_7'] = np.random.uniform(0, 1)
            features['feature_8'] = np.random.uniform(0, 10) 
            features['feature_9'] = np.random.exponential(2)
            
            return features
            
        except Exception as e:
            st.error(f"Feature extraction error: {str(e)}")
            return {name: 0 for name in self.feature_names}
    
    def predict_malware(self, analysis_results):
        """Predict if file is malware using ML models"""
        try:
            features = self.extract_ml_features(analysis_results)
            
            feature_df = pd.DataFrame([features])
            feature_df = feature_df.reindex(columns=self.feature_names, fill_value=0)
            
            if 'malware' in self.scalers:
                features_scaled = self.scalers['malware'].transform(feature_df)
            else:
                features_scaled = feature_df.values
            
            results = {
                'timestamp': datetime.now().isoformat(),
                'features_used': features,
                'models_available': list(self.models.keys())
            }
            
            if 'malware_classifier' in self.models:
                malware_prob = self.models['malware_classifier'].predict_proba(features_scaled)[0]
                results['malware_probability'] = float(malware_prob[1])
                results['malware_prediction'] = bool(malware_prob[1] > 0.5)
                results['confidence'] = float(max(malware_prob))
            else:
                results['malware_probability'] = 0.0
                results['malware_prediction'] = False
                results['confidence'] = 0.0
            
            if 'anomaly_detector' in self.models:
                anomaly_score = self.models['anomaly_detector'].decision_function(features_scaled)[0]
                results['anomaly_score'] = float(anomaly_score)
                results['is_anomaly'] = bool(anomaly_score < 0)
            else:
                results['anomaly_score'] = 0.0
                results['is_anomaly'] = False
            
            if hasattr(self.models.get('malware_classifier'), 'feature_importances_'):
                importances = self.models['malware_classifier'].feature_importances_
                results['feature_importance'] = dict(zip(self.feature_names, importances.astype(float)))
            
            return results
            
        except Exception as e:
            st.error(f"ML prediction error: {str(e)}")
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'malware_probability': 0.0,
                'malware_prediction': False,
                'confidence': 0.0,
                'anomaly_score': 0.0,
                'is_anomaly': False
            }
    
    def analyze_network_anomalies(self, network_data):
        """Analyze network traffic for anomalies using ML"""
        try:
            if not network_data:
                return {'error': 'No network data provided'}
            
            features = []
            for connection in network_data:
                feature_vector = [
                    connection.get('bytes_sent', 0),
                    connection.get('bytes_recv', 0),
                    connection.get('packets_sent', 0),
                    connection.get('packets_recv', 0),
                    connection.get('duration', 0),
                    len(connection.get('remote_ip', '')),
                    connection.get('remote_port', 0),
                    connection.get('protocol_score', 0)
                ]
                features.append(feature_vector)
            
            if not features:
                return {'error': 'No features extracted from network data'}
            
            if 'anomaly_detector' in self.models:
                anomaly_scores = self.models['anomaly_detector'].decision_function(features)
                anomalies = anomaly_scores < 0
                
                return {
                    'total_connections': len(features),
                    'anomalous_connections': int(sum(anomalies)),
                    'anomaly_percentage': float(sum(anomalies) / len(anomalies) * 100),
                    'anomaly_scores': [float(score) for score in anomaly_scores],
                    'anomaly_threshold': 0.0
                }
            else:
                return {'error': 'Anomaly detector not available'}
                
        except Exception as e:
            return {'error': f'Network anomaly analysis failed: {str(e)}'}
    
    def get_model_info(self):
        """Get information about loaded models"""
        info = {
            'models_loaded': list(self.models.keys()),
            'feature_count': len(self.feature_names),
            'feature_names': self.feature_names,
            'scalers_available': list(self.scalers.keys())
        }
        
        for name, model in self.models.items():
            model_info = {
                'type': type(model).__name__,
                'parameters': getattr(model, 'get_params', lambda: {})()
            }
            info[f'{name}_info'] = model_info
        
        return info
