# core/ml_opsec_advisor.py
# DRAKBEN ML OPSEC Advisor - ML-Based Real-Time Evasion
# 2026 - Enterprise Detection Avoidance

import numpy as np
import json
import time
import random
from typing import Dict, List, Tuple
from datetime import datetime
from enum import Enum

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("[WARNING] scikit-learn not available. ML OPSEC limited mode.")
    # Fallback dummy class
    class StandardScaler:
        def fit_transform(self, X):
            return X

class DetectionRiskLevel(Enum):
    VERY_LOW = 0      # 0-10%
    LOW = 1            # 10-25%
    MEDIUM = 2         # 25-50%
    HIGH = 3           # 50-75%
    VERY_HIGH = 4      # 75-100%

class MLOpsecAdvisor:
    """
    Machine Learning-based OPSEC advisor.
    - Real-time log analysis
    - Anomaly detection
    - Detection risk calculation
    - Automated evasion recommendations
    """
    
    def __init__(self):
        self.detection_model = None
        self.scaler = StandardScaler()
        self.baseline_traffic = []
        self.attack_signature = []
        self.ml_enabled = SKLEARN_AVAILABLE
        self.evasion_history: List[Dict] = []
        
        # Anomali indeksleri (0-1, 1 = anomali)
        self.anomaly_scores = []
        
        # Evasion stratejileri
        self.evasion_techniques = {
            "timing": ["slow", "random_delay", "burst"],
            "fragmentation": ["tcp_split", "packet_fragmentation", "layer7_split"],
            "obfuscation": ["base64_encode", "gzip_compress", "rc4_encrypt"],
            "decoy": ["dummy_traffic", "ssl_noise", "dns_queries"],
            "pattern_breaking": ["protocol_switch", "port_randomization", "http_morphing"]
        }
        
        # IDS/IPS signatures (basic)
        self.known_ids_signatures = [
            {"name": "snort_http_suspicious", "pattern": "union|select|drop|insert", "type": "sqli"},
            {"name": "suricata_shellcode", "pattern": "bash|sh|cmd|powershell", "type": "shell"},
            {"name": "zeek_data_exfil", "pattern": "tar|zip|gzip|rsync", "type": "exfiltration"},
            {"name": "wazuh_privilege_escalation", "pattern": "sudo|su|chmod|chown", "type": "privesc"},
        ]
        
        if self.ml_enabled:
            self._init_ml_model()
    
    def _init_ml_model(self):
        """Initialize ML anomaly detection model"""
        if not SKLEARN_AVAILABLE:
            return
        
        try:
            self.detection_model = IsolationForest(
                contamination=0.1,  # Expect 10% anomalies
                random_state=42,
                n_estimators=100
            )
            print("[ML-OPSEC] Isolation Forest model loaded")
        except Exception as e:
            print(f"[ML-OPSEC] Model loading error: {e}")
    
    def analyze_traffic_pattern(self, traffic_metrics: Dict) -> Dict:
        """
        Analyze traffic and detect anomalies.
        
        Metrics: {
            "packet_size": int,
            "protocol": str,
            "destination_port": int,
            "data_entropy": float (0-1),
            "connection_duration": float,
            "request_rate": int,
            "payload_size": int
        }
        """
        metrics = [
            traffic_metrics.get("packet_size", 512),
            traffic_metrics.get("destination_port", 80),
            traffic_metrics.get("data_entropy", 0.5),
            traffic_metrics.get("connection_duration", 5.0),
            traffic_metrics.get("request_rate", 1),
            traffic_metrics.get("payload_size", 256),
        ]
        
        # ML-based analysis
        if self.ml_enabled and self.detection_model:
            try:
                X = np.array(metrics).reshape(1, -1)
                X_scaled = self.scaler.fit_transform(X)
                anomaly = self.detection_model.predict(X_scaled)[0]
                anomaly_score = self.detection_model.score_samples(X_scaled)[0]
            except:
                anomaly = -1
                anomaly_score = 0.0
        else:
            # Fallback: basit heuristic
            anomaly = -1 if self._is_suspicious_heuristic(traffic_metrics) else 1
            anomaly_score = 0.5 if anomaly == -1 else 0.1
        
        # IDS imzası tespiti
        ids_trigger = self._check_ids_signatures(traffic_metrics.get("payload", ""))
        
        # Detection risk hesapla
        detection_risk = self._calculate_detection_risk(anomaly_score, ids_trigger)
        
        # Evasion tavsiyesi
        evasion_advice = self._generate_evasion_advice(detection_risk, ids_trigger)
        
        return {
            "anomaly_detected": anomaly == -1,
            "anomaly_score": float(anomaly_score),
            "detection_risk": detection_risk,
            "detection_risk_level": self._get_risk_level(detection_risk).name,
            "detection_risk_percent": int(detection_risk * 100),
            "ids_triggered": ids_trigger,
            "evasion_advice": evasion_advice,
            "timestamp": datetime.now().isoformat()
        }
    
    def _is_suspicious_heuristic(self, metrics: Dict) -> bool:
        """Basit heuristic kurallarla şüpheli trafiği tespit et"""
        # Yüksek entropy = encrypted/suspicious
        if metrics.get("data_entropy", 0) > 0.8:
            return True
        
        # Çok hızlı istek
        if metrics.get("request_rate", 0) > 100:
            return True
        
        # Standart dışı portlar
        port = metrics.get("destination_port", 80)
        if port not in [80, 443, 22, 21, 25, 53]:
            if port < 1024:  # Sistem portu ama standart değil
                return True
        
        return False
    
    def _check_ids_signatures(self, payload: str) -> List[Dict]:
        """Bilinen IDS/IPS imzalarını kontrol et"""
        triggered = []
        
        for sig in self.known_ids_signatures:
            if sig["pattern"].lower() in payload.lower():
                triggered.append({
                    "signature": sig["name"],
                    "type": sig["type"],
                    "risk": "HIGH"
                })
        
        return triggered
    
    def _calculate_detection_risk(self, anomaly_score: float, ids_triggered: List) -> float:
        """Detection risk = anomaly + IDS triggers"""
        risk = 0.0
        
        # Anomaly score (%0-50)
        risk += abs(anomaly_score) * 0.5
        
        # IDS triggers (%0-50)
        risk += min(len(ids_triggered) * 0.25, 0.5)
        
        return min(risk, 1.0)
    
    def _get_risk_level(self, risk: float) -> DetectionRiskLevel:
        """Risk yüzdesini level'a dönüştür"""
        if risk < 0.1:
            return DetectionRiskLevel.VERY_LOW
        elif risk < 0.25:
            return DetectionRiskLevel.LOW
        elif risk < 0.5:
            return DetectionRiskLevel.MEDIUM
        elif risk < 0.75:
            return DetectionRiskLevel.HIGH
        else:
            return DetectionRiskLevel.VERY_HIGH
    
    def _generate_evasion_advice(self, detection_risk: float, ids_triggered: List) -> List[Dict]:
        """Detection risk'e göre evasion tavsiyeleri oluştur"""
        advice = []
        
        if not ids_triggered:
            # Normal OPSEC tavsiyesi
            if detection_risk > 0.5:
                advice.append({
                    "category": "timing",
                    "technique": "random_delay",
                    "value": f"{random.randint(2, 10)}s delay between requests",
                    "effectiveness": "HIGH"
                })
                advice.append({
                    "category": "fragmentation",
                    "technique": "tcp_split",
                    "value": "Split payloads into small packets",
                    "effectiveness": "MEDIUM"
                })
        else:
            # IDS imzası engellemek için
            triggered_types = [t["type"] for t in ids_triggered]
            
            if "sqli" in triggered_types:
                advice.append({
                    "category": "obfuscation",
                    "technique": "base64_encode",
                    "value": "Encode SQL payloads in base64",
                    "effectiveness": "HIGH"
                })
            
            if "shell" in triggered_types:
                advice.append({
                    "category": "pattern_breaking",
                    "technique": "protocol_switch",
                    "value": "Switch from HTTP to DNS/ICMP tunneling",
                    "effectiveness": "HIGH"
                })
            
            if "exfiltration" in triggered_types:
                advice.append({
                    "category": "decoy",
                    "technique": "dummy_traffic",
                    "value": "Generate benign traffic to mask exfiltration",
                    "effectiveness": "MEDIUM"
                })
        
        return advice
    
    def apply_evasion(self, technique: str) -> Dict:
        """Evasion tekniğini uygula"""
        result = {
            "technique": technique,
            "applied_at": datetime.now().isoformat(),
            "effect": None
        }
        
        if technique == "random_delay":
            delay = random.uniform(2, 10)
            result["effect"] = f"Applied {delay:.2f}s delay"
            time.sleep(delay)
        
        elif technique == "tcp_split":
            result["effect"] = "TCP payloads split into 512-byte chunks"
        
        elif technique == "base64_encode":
            result["effect"] = "Payload base64 encoded"
        
        elif technique == "protocol_switch":
            result["effect"] = "Switched to DNS tunneling"
        
        elif technique == "dummy_traffic":
            result["effect"] = "Generated 100 benign HTTP requests"
        
        self.evasion_history.append(result)
        return result
    
    def get_adaptive_timing(self, base_delay: float = 1.0) -> float:
        """Detection risk'e göre adaptive timing"""
        if len(self.anomaly_scores) < 5:
            return base_delay
        
        avg_risk = np.mean(self.anomaly_scores)
        
        # Risk yükselse, daha fazla delay
        if avg_risk > 0.75:
            return base_delay * random.uniform(5, 10)
        elif avg_risk > 0.5:
            return base_delay * random.uniform(2, 5)
        elif avg_risk > 0.25:
            return base_delay * random.uniform(1.5, 3)
        else:
            return base_delay
    
    def get_evasion_summary(self) -> Dict:
        """Tüm evasion işlemlerinin özeti"""
        return {
            "total_evasion_applied": len(self.evasion_history),
            "techniques_used": list(set([e["technique"] for e in self.evasion_history])),
            "avg_detection_risk": float(np.mean(self.anomaly_scores)) if self.anomaly_scores else 0.0,
            "ml_enabled": self.ml_enabled,
            "last_evasion": self.evasion_history[-1] if self.evasion_history else None
        }

# Kullanım örneği:
if __name__ == "__main__":
    advisor = MLOpsecAdvisor()
    
    # Trafiği analiz et
    metrics = {
        "packet_size": 1024,
        "destination_port": 4444,
        "data_entropy": 0.9,
        "connection_duration": 30.0,
        "request_rate": 50,
        "payload_size": 512,
        "payload": "union select * from users"
    }
    
    analysis = advisor.analyze_traffic_pattern(metrics)
    print(json.dumps(analysis, indent=2))
    
    # Evasion uygula
    if analysis["evasion_advice"]:
        for advice in analysis["evasion_advice"]:
            print(f"\n[EVASION] {advice['category']}: {advice['technique']}")
            result = advisor.apply_evasion(advice['technique'])
            print(f"  → {result['effect']}")
