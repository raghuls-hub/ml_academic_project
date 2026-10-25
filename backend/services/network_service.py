"""
Network Intrusion Inspector Service (NSL-KDD Module)
Evaluates flow-level and packet-level telemetry using Random Forest classification.
Computes Network Threat Probability via predict_proba() and classifies intrusion categories.
"""

import logging
from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd
import joblib

from config import Config

logger = logging.getLogger("soc.network_service")

# Key NSL-KDD Features used in the model
NUMERICAL_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]

# Attack taxonomies for NSL-KDD
ATTACK_TYPES = {
    "dos": ["neptune", "smurf", "pod", "teardrop", "land", "back", "apache2", "udpstorm", "processtable", "mailbomb"],
    "probe": ["portsweep", "ipsweep", "nmap", "satan", "saint", "mscan"],
    "r2l": ["guess_passwd", "ftp_write", "imap", "phf", "multihop", "warezmaster", "warezclient", "spy", "xlock", "xsnoop", "snmpguess", "snmpgetattack", "httptunnel", "sendmail", "named"],
    "u2r": ["buffer_overflow", "loadmodule", "rootkit", "perl", "sqlattack", "xterm", "ps"]
}

class NetworkService:
    """Inference service for NSL-KDD Network Intrusion Inspection."""

    def __init__(self):
        self.model = None
        self.scaler = None
        self.encoders = None
        self.is_fallback_active = False
        self._load_artifacts()

    def _load_artifacts(self) -> None:
        """Loads trained Network IDS artifacts or sets up robust fallback mode."""
        try:
            if (Config.NETWORK_IDS_MODEL_PATH.exists() and 
                Config.NETWORK_SCALER_PATH.exists() and 
                Config.NETWORK_ENCODERS_PATH.exists()):
                
                logger.info("Loading NSL-KDD network models from %s", Config.ARTIFACTS_PATH)
                self.model = joblib.load(Config.NETWORK_IDS_MODEL_PATH)
                self.scaler = joblib.load(Config.NETWORK_SCALER_PATH)
                self.encoders = joblib.load(Config.NETWORK_ENCODERS_PATH)
                self.is_fallback_active = False
                logger.info("Network IDS models successfully loaded.")
            else:
                missing = []
                for p in [Config.NETWORK_IDS_MODEL_PATH, Config.NETWORK_SCALER_PATH, Config.NETWORK_ENCODERS_PATH]:
                    if not p.exists():
                        missing.append(p.name)
                logger.warning(
                    "Missing network artifacts: %s. Initializing robust fallback heuristic pipeline.",
                    ", ".join(missing)
                )
                self.is_fallback_active = True
        except Exception as e:
            logger.error("Failed to load network IDS artifacts: %s. Enabling fallback mode.", e)
            self.is_fallback_active = True

    def _encode_categorical(self, col: str, val: Any) -> float:
        """Encode categorical feature safely handling unseen labels."""
        val_str = str(val).lower().strip()
        if self.encoders and col in self.encoders:
            enc = self.encoders[col]
            if hasattr(enc, "transform"):
                try:
                    return float(enc.transform([val_str])[0])
                except Exception:
                    return 0.0
            elif isinstance(enc, dict):
                return float(enc.get(val_str, 0.0))
        
        # Default numeric mappings for fallbacks
        defaults = {
            "protocol_type": {"tcp": 0, "udp": 1, "icmp": 2},
            "service": {"http": 0, "private": 1, "smtp": 2, "ftp_data": 3, "other": 4, "telnet": 5, "eco_i": 6, "finger": 7},
            "flag": {"sf": 0, "s0": 1, "rej": 2, "rsto": 3, "rstos0": 4, "rstr": 5, "s1": 6, "s2": 7, "s3": 8}
        }
        return float(defaults.get(col, {}).get(val_str, 0.0))

    def _preprocess_input(self, data: Dict[str, Any]) -> np.ndarray:
        """Transforms raw network flow dictionary into scaled feature vector."""
        cat_vals = [self._encode_categorical(c, data.get(c, "")) for c in CATEGORICAL_FEATURES]
        num_vals = [float(data.get(f, 0.0)) for f in NUMERICAL_FEATURES]
        full_vector = np.array([cat_vals + num_vals], dtype=np.float32)

        if not self.is_fallback_active and self.scaler:
            try:
                return self.scaler.transform(full_vector)
            except Exception as e:
                logger.warning("Error transforming network features: %s", e)

        return full_vector

    def _fallback_network_inference(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        High-fidelity heuristic analyzer for NSL-KDD network flows when ML models are not present.
        Accurately flags SYN floods (DoS), Portsweeps (Probes), Brute-forces (R2L), and root escalations (U2R).
        """
        serror_rate = float(data.get("serror_rate", 0.0))
        rerror_rate = float(data.get("rerror_rate", 0.0))
        flag = str(data.get("flag", "SF")).upper()
        count = float(data.get("count", 1.0))
        srv_count = float(data.get("srv_count", 1.0))
        diff_srv_rate = float(data.get("diff_srv_rate", 0.0))
        dst_bytes = float(data.get("dst_bytes", 0.0))
        src_bytes = float(data.get("src_bytes", 0.0))
        failed_logins = float(data.get("num_failed_logins", 0.0))
        root_shell = float(data.get("root_shell", 0.0))
        su_attempted = float(data.get("su_attempted", 0.0))
        protocol = str(data.get("protocol_type", "tcp")).lower()
        service = str(data.get("service", "http")).lower()

        score = 0.05
        attack_type = "Normal"
        confidence = 0.90

        # Heuristic 1: SYN Flood / DoS Indicators
        if flag == "S0" or serror_rate > 0.50 or (count > 150 and serror_rate > 0.3):
            score = 0.92
            attack_type = "DoS (Denial of Service - SYN Flood)"
        # Heuristic 2: Portscan / Probe Indicators
        elif diff_srv_rate > 0.60 or (count > 50 and srv_count < 5) or flag in ["REJ", "RSTO"]:
            score = 0.82
            attack_type = "Probe (Network Scan / Portsweep)"
        # Heuristic 3: U2R (User to Root) Exploit
        elif root_shell == 1.0 or su_attempted == 1.0:
            score = 0.96
            attack_type = "U2R (User to Root Privilege Escalation)"
        # Heuristic 4: R2L (Remote to Local / Brute Force)
        elif failed_logins > 2.0 or (service in ["telnet", "ftp"] and failed_logins >= 1.0):
            score = 0.78
            attack_type = "R2L (Remote to Local / Credential Brute Force)"
        # Heuristic 5: Anomalous byte asymmetry or high data volume
        elif src_bytes > 50000 and dst_bytes < 100:
            score = 0.68
            attack_type = "Data Exfiltration / UDP Flood"
        else:
            score = 0.08
            attack_type = "Normal Flow"

        threat_detected = int(score >= Config.NETWORK_THREAT_THRESHOLD)

        return {
            "threat_probability": round(score, 4),
            "threat_detected": threat_detected,
            "attack_category": attack_type,
            "confidence": confidence
        }

    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main analysis method for Network telemetry.
        Returns prediction, threat probability (predict_proba), and attack classification.
        """
        if not self.is_fallback_active and self.model:
            try:
                features = self._preprocess_input(data)
                probabilities = self.model.predict_proba(features)[0]
                prediction = int(self.model.predict(features)[0])
                
                # Malicious class probability (class index 1 if binary)
                threat_prob = float(probabilities[1]) if len(probabilities) > 1 else float(probabilities[0])
                threat_detected = int(threat_prob >= Config.NETWORK_THREAT_THRESHOLD or prediction == 1)

                # Determine attack category label
                if threat_detected == 1:
                    attack_category = "Intrusion Attempt"
                    if hasattr(self.model, "classes_") and len(self.model.classes_) > 2:
                        predicted_class_name = str(self.model.classes_[np.argmax(probabilities)])
                        attack_category = predicted_class_name
                else:
                    attack_category = "Normal Flow"

                risk_level = "CRITICAL" if threat_prob >= 0.80 else ("HIGH" if threat_prob >= 0.60 else ("MEDIUM" if threat_prob >= 0.40 else "LOW"))

                return {
                    "module": "NSL-KDD Network Intrusion Inspector",
                    "threat_probability": round(threat_prob, 4),
                    "threat_detected": threat_detected,
                    "prediction": prediction,
                    "attack_category": attack_category,
                    "risk_level": risk_level,
                    "threshold": Config.NETWORK_THREAT_THRESHOLD,
                    "fallback_mode": False,
                    "telemetry_summary": {
                        "protocol_type": data.get("protocol_type", "tcp"),
                        "service": data.get("service", "http"),
                        "flag": data.get("flag", "SF"),
                        "src_bytes": data.get("src_bytes", 0),
                        "dst_bytes": data.get("dst_bytes", 0),
                        "count": data.get("count", 1),
                        "serror_rate": data.get("serror_rate", 0.0)
                    }
                }
            except Exception as e:
                logger.error("Error during network model inference: %s. Using heuristic.", e)

        # Fallback Heuristics
        fallback_res = self._fallback_network_inference(data)
        threat_prob = fallback_res["threat_probability"]
        threat_detected = fallback_res["threat_detected"]
        risk_level = "CRITICAL" if threat_prob >= 0.80 else ("HIGH" if threat_prob >= 0.60 else ("MEDIUM" if threat_prob >= 0.40 else "LOW"))

        return {
            "module": "NSL-KDD Network Intrusion Inspector",
            "threat_probability": threat_prob,
            "threat_detected": threat_detected,
            "prediction": threat_detected,
            "attack_category": fallback_res["attack_category"],
            "risk_level": risk_level,
            "threshold": Config.NETWORK_THREAT_THRESHOLD,
            "fallback_mode": True,
            "telemetry_summary": {
                "protocol_type": data.get("protocol_type", "tcp"),
                "service": data.get("service", "http"),
                "flag": data.get("flag", "SF"),
                "src_bytes": data.get("src_bytes", 0),
                "dst_bytes": data.get("dst_bytes", 0),
                "count": data.get("count", 1),
                "serror_rate": data.get("serror_rate", 0.0)
            }
        }

    def analyze_batch(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Processes a batch DataFrame of network flow logs (e.g. from CSV upload)."""
        results = []
        threats_count = 0
        probabilities = []

        for idx, row in df.iterrows():
            row_dict = row.to_dict()
            res = self.analyze(row_dict)
            results.append({
                "row_index": idx,
                "protocol": row_dict.get("protocol_type", "tcp"),
                "service": row_dict.get("service", "other"),
                "flag": row_dict.get("flag", "SF"),
                "threat_probability": res["threat_probability"],
                "attack_category": res["attack_category"],
                "risk_level": res["risk_level"],
                "threat_detected": res["threat_detected"]
            })
            probabilities.append(res["threat_probability"])
            if res["threat_detected"] == 1:
                threats_count += 1

        avg_threat = round(float(np.mean(probabilities)), 4) if probabilities else 0.0
        max_threat = round(float(np.max(probabilities)), 4) if probabilities else 0.0

        return {
            "total_records": len(df),
            "threats_detected": threats_count,
            "threat_rate_percent": round((threats_count / max(len(df), 1)) * 100, 2),
            "avg_threat_probability": avg_threat,
            "max_threat_probability": max_threat,
            "records": results[:100],
            "fallback_mode": self.is_fallback_active
        }


# Singleton instance
network_service = NetworkService()

