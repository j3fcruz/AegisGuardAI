# utils/train_model.py
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import pickle
import os
from datetime import datetime

def train_and_save_models(model_path='data/models/malware_features.pkl'):
    """
    Trains machine learning models for malware detection and saves them to disk.
    """
    print("Starting ML model training...")

    # Generate synthetic training data
    np.random.seed(42)
    n_samples = 1000
    
    features = []
    labels = []
    
    for i in range(n_samples):
        file_size = np.random.lognormal(10, 2)
        entropy = np.random.uniform(0, 8)
        num_sections = np.random.poisson(5)
        suspicious_imports = np.random.poisson(2)
        yara_matches = np.random.poisson(1)
        pe_suspicious_flags = np.random.poisson(1)
        
        feature_vector = [
            file_size, entropy, num_sections, suspicious_imports,
            yara_matches, pe_suspicious_flags, np.random.uniform(0, 1),
            np.random.uniform(0, 10), np.random.exponential(2)
        ]
        
        is_malware = (
            (entropy > 7.5) or (suspicious_imports > 3) or
            (yara_matches > 2) or (pe_suspicious_flags > 2)
        )
        
        features.append(feature_vector)
        labels.append(1 if is_malware else 0)
    
    feature_names = [
        'file_size', 'entropy', 'num_sections', 'suspicious_imports',
        'yara_matches', 'pe_suspicious_flags', 'feature_7', 'feature_8', 'feature_9'
    ]
    
    df = pd.DataFrame(features, columns=feature_names)
    
    X_train, X_test, y_train, y_test = train_test_split(df, labels, test_size=0.2, random_state=42)
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train Random Forest classifier
    malware_classifier = RandomForestClassifier(
        n_estimators=100, random_state=42, class_weight='balanced'
    )
    malware_classifier.fit(X_train_scaled, y_train)
    
    # Train Isolation Forest for anomaly detection
    anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
    anomaly_detector.fit(X_train_scaled)
    
    train_accuracy = malware_classifier.score(X_train_scaled, y_train)
    test_accuracy = malware_classifier.score(X_test_scaled, y_test)
    
    print(f"ML models trained successfully!")
    print(f"Train Accuracy: {train_accuracy:.3f}")
    print(f"Test Accuracy: {test_accuracy:.3f}")
    
    # Save models and scaler
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    
    model_data = {
        'models': {
            'malware_classifier': malware_classifier,
            'anomaly_detector': anomaly_detector
        },
        'scalers': {
            'malware': scaler
        },
        'feature_names': feature_names,
        'timestamp': datetime.now().isoformat()
    }
    
    with open(model_path, 'wb') as f:
        pickle.dump(model_data, f)
    print(f"Models saved to {model_path}")

if __name__ == "__main__":
    train_and_save_models()
