"""
Machine Learning Vulnerability Detector
Uses ML models to detect vulnerabilities in smart contracts
"""

import os
import json
import pandas as pd
import numpy as np
import pickle
import logging
from typing import Dict, List, Optional, Tuple
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

class MLVulnerabilityDetector:
    """ML-powered vulnerability detection for smart contracts"""
    
    def __init__(self):
        self.models = {}
        self.vectorizers = {}
        self.scalers = {}
        self.vulnerability_types = [
            'reentrancy',
            'integer_overflow', 
            'access_control',
            'unchecked_external_calls',
            'denial_of_service',
            'timestamp_dependence'
        ]
        self.model_path = "smartsploit/lib/models"
        self._ensure_model_directory()
        
    def _ensure_model_directory(self):
        """Create models directory if it doesn't exist"""
        os.makedirs(self.model_path, exist_ok=True)
        
    def extract_bytecode_features(self, bytecode: str) -> np.ndarray:
        """Extract features from contract bytecode"""
        if not bytecode or bytecode == '0x':
            return np.zeros(50)  # Return zero vector for empty bytecode
            
        # Remove 0x prefix if present
        if bytecode.startswith('0x'):
            bytecode = bytecode[2:]
            
        features = []
        
        # Opcode frequency features
        opcodes = {
            'CALL': 'f1', 'DELEGATECALL': 'f4', 'STATICCALL': 'fa',
            'SLOAD': '54', 'SSTORE': '55', 'MLOAD': '51', 'MSTORE': '52',
            'JUMP': '56', 'JUMPI': '57', 'REVERT': 'fd', 'SELFDESTRUCT': 'ff',
            'CREATE': 'f0', 'CREATE2': 'f5', 'EXTCODESIZE': '3b'
        }
        
        for opcode, hex_code in opcodes.items():
            count = bytecode.count(hex_code)
            features.append(count)
            
        # Bytecode length and complexity
        features.extend([
            len(bytecode),
            len(set(bytecode)),  # Unique byte count
            bytecode.count('00'),  # Null byte count
            bytecode.count('ff'),  # Max byte count
        ])
        
        # Pattern-based features
        features.extend([
            1 if 'f1' in bytecode and '54' in bytecode else 0,  # CALL + SLOAD
            1 if 'f4' in bytecode else 0,  # DELEGATECALL present
            1 if bytecode.count('f1') > 3 else 0,  # Multiple external calls
            1 if '3b' in bytecode and 'f1' in bytecode else 0,  # Size check + call
        ])
        
        # Statistical features
        byte_values = [int(bytecode[i:i+2], 16) for i in range(0, len(bytecode), 2) if i+1 < len(bytecode)]
        if byte_values:
            features.extend([
                np.mean(byte_values),
                np.std(byte_values),
                np.max(byte_values),
                np.min(byte_values)
            ])
        else:
            features.extend([0, 0, 0, 0])
            
        # Pad or truncate to fixed size
        while len(features) < 50:
            features.append(0)
        return np.array(features[:50])
        
    def train_models(self, training_data_path: str) -> None:
        """Train ML models using training data"""
        try:
            # Load training data
            if training_data_path.endswith('.csv'):
                df = pd.read_csv(training_data_path)
            elif training_data_path.endswith('.json'):
                df = pd.read_json(training_data_path)
            else:
                logger.error("Unsupported training data format")
                return
                
            logger.info(f"Loaded {len(df)} training samples")
            
            # Extract features from bytecode
            X = np.array([self.extract_bytecode_features(bytecode) for bytecode in df['bytecode']])
            
            # Train models for each vulnerability type
            for vuln_type in self.vulnerability_types:
                if vuln_type in df.columns:
                    y = df[vuln_type].astype(int)
                    
                    # Split data
                    X_train, X_test, y_train, y_test = train_test_split(
                        X, y, test_size=0.2, random_state=42, stratify=y
                    )
                    
                    # Scale features
                    scaler = StandardScaler()
                    X_train_scaled = scaler.fit_transform(X_train)
                    X_test_scaled = scaler.transform(X_test)
                    
                    # Train model
                    model = RandomForestClassifier(
                        n_estimators=100,
                        random_state=42,
                        class_weight='balanced'
                    )
                    model.fit(X_train_scaled, y_train)
                    
                    # Evaluate
                    y_pred = model.predict(X_test_scaled)
                    report = classification_report(y_test, y_pred, output_dict=True)
                    
                    logger.info(f"Model {vuln_type} - Accuracy: {report['accuracy']:.3f}")
                    
                    # Save model and scaler
                    self.models[vuln_type] = model
                    self.scalers[vuln_type] = scaler
                    
                    # Persist to disk
                    model_file = os.path.join(self.model_path, f"{vuln_type}_model.pkl")
                    scaler_file = os.path.join(self.model_path, f"{vuln_type}_scaler.pkl")
                    
                    with open(model_file, 'wb') as f:
                        pickle.dump(model, f)
                    with open(scaler_file, 'wb') as f:
                        pickle.dump(scaler, f)
                        
            logger.info("Model training completed")
            
        except Exception as e:
            logger.error(f"Error training models: {e}")
            
    def load_models(self) -> None:
        """Load pre-trained models from disk"""
        for vuln_type in self.vulnerability_types:
            model_file = os.path.join(self.model_path, f"{vuln_type}_model.pkl")
            scaler_file = os.path.join(self.model_path, f"{vuln_type}_scaler.pkl")
            
            if os.path.exists(model_file) and os.path.exists(scaler_file):
                try:
                    with open(model_file, 'rb') as f:
                        self.models[vuln_type] = pickle.load(f)
                    with open(scaler_file, 'rb') as f:
                        self.scalers[vuln_type] = pickle.load(f)
                    logger.info(f"Loaded model for {vuln_type}")
                except Exception as e:
                    logger.error(f"Error loading model {vuln_type}: {e}")
                    
    def predict_vulnerabilities(self, bytecode: str) -> Dict[str, float]:
        """Predict vulnerabilities in contract bytecode"""
        results = {}
        
        # Extract features
        features = self.extract_bytecode_features(bytecode)
        features = features.reshape(1, -1)
        
        # Predict for each vulnerability type
        for vuln_type in self.vulnerability_types:
            if vuln_type in self.models and vuln_type in self.scalers:
                try:
                    # Scale features
                    features_scaled = self.scalers[vuln_type].transform(features)
                    
                    # Predict probability
                    prob = self.models[vuln_type].predict_proba(features_scaled)[0][1]
                    results[vuln_type] = float(prob)
                    
                except Exception as e:
                    logger.error(f"Error predicting {vuln_type}: {e}")
                    results[vuln_type] = 0.0
            else:
                # Return heuristic score if no model available
                results[vuln_type] = self._heuristic_score(bytecode, vuln_type)
                
        return results
        
    def _heuristic_score(self, bytecode: str, vuln_type: str) -> float:
        """Calculate heuristic vulnerability score"""
        if not bytecode or bytecode == '0x':
            return 0.0
            
        bytecode = bytecode.lower()
        
        # Simple pattern-based scoring
        patterns = {
            'reentrancy': ['f1', '54'],  # CALL + SLOAD
            'integer_overflow': ['01', '02', '03'],  # ADD, MUL, SUB
            'access_control': ['33', 'f4'],  # CALLER, DELEGATECALL
            'unchecked_external_calls': ['f1', 'fa'],  # CALL, STATICCALL
            'denial_of_service': ['5b', 'fd'],  # JUMPDEST, REVERT
            'timestamp_dependence': ['42']  # TIMESTAMP
        }
        
        if vuln_type in patterns:
            score = 0.0
            for pattern in patterns[vuln_type]:
                if pattern in bytecode:
                    score += 0.3
            return min(score, 1.0)
            
        return 0.1  # Default low score
        
    def calculate_risk_score(self, vulnerabilities: Dict[str, float]) -> Tuple[float, str]:
        """Calculate overall risk score and classification"""
        # Weighted scoring
        weights = {
            'reentrancy': 0.25,
            'integer_overflow': 0.20,
            'access_control': 0.20,
            'unchecked_external_calls': 0.15,
            'denial_of_service': 0.10,
            'timestamp_dependence': 0.10
        }
        
        weighted_score = sum(
            vulnerabilities.get(vuln, 0) * weight 
            for vuln, weight in weights.items()
        )
        
        # Classify risk level
        if weighted_score >= 0.7:
            risk_level = "HIGH"
        elif weighted_score >= 0.4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
            
        return weighted_score, risk_level
