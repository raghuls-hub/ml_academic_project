"""
Host Syscall & Payload Security Service (BETH Module)
Combines kernel-level behavioral anomaly detection (Isolation Forest)
with NLP payload threat classification (TF-IDF + Logistic Regression).
Calculates a composite threat score: (0.50 * Host Isolation Score) + (0.50 * Payload TF-IDF Threat Probability).
"""

import os
import re
import math
import logging
from typing import Dict, Any, List, Tuple, Optional
import numpy as np
import pandas as pd
import joblib

from config import Config

logger = logging.getLogger("soc.host_service")

# Feature definitions for BETH Host behavioral model
HOST_FEATURE_COLUMNS = [
    "processId",
    "parentProcessId",
    "userId",
    "mountNamespace",
    "eventId",
    "argsNum",
    "returnValue",
    "suspendCount"
]

# High-risk syscall event IDs / names commonly monitored in BETH
SUSPICIOUS_EVENT_IDS = {59, 101, 157, 165, 175, 313, 319, 105, 106}  # execve, ptrace, init_module, etc.
SUSPICIOUS_PAYLOAD_KEYWORDS = [
    r"/bin/sh", r"/bin/bash", r"nc\s+-e", r"bash\s+-i", r"/dev/tcp/",
    r"curl\s+.*\|\s*bash", r"wget\s+.*\|\s*sh", r"chmod\s+777", r"chmod\s+\+x",
    r"base64\s+-d", r"python\s+-c\s+['\"].*socket", r"perl\s+-e",
    r"sudo\s+cat\s+/etc/shadow", r"cat\s+/etc/passwd", r"useradd", r"iptables\s+-F",
    r"systemctl\s+stop\s+firewalld", r"powershell\s+-enc", r"mimikatz", r"certutil"
]

class HostService:
    """Inference service for Host Syscall & Payload security analysis."""

    def __init__(self):
        self.isolation_forest = None
        self.scaler = None
        self.payload_classifier = None
        self.tfidf_vectorizer = None
        self.is_fallback_active = False
        self._load_artifacts()

    def _load_artifacts(self) -> None:
        """Attempt to load trained artifacts from disk; fallback to heuristics if unavailable."""
        try:
            if (Config.HOST_ISOLATION_FOREST_PATH.exists() and 
                Config.HOST_SCALER_PATH.exists() and 
                Config.PAYLOAD_CLASSIFIER_PATH.exists() and 
                Config.TFIDF_VECTORIZER_PATH.exists()):
                
                logger.info("Loading BETH host security artifacts from %s", Config.ARTIFACTS_PATH)
                self.isolation_forest = joblib.load(Config.HOST_ISOLATION_FOREST_PATH)
                self.scaler = joblib.load(Config.HOST_SCALER_PATH)
                self.payload_classifier = joblib.load(Config.PAYLOAD_CLASSIFIER_PATH)
                self.tfidf_vectorizer = joblib.load(Config.TFIDF_VECTORIZER_PATH)
                self.is_fallback_active = False
                logger.info("Host security models successfully loaded.")
            else:
                missing = []
                for p in [Config.HOST_ISOLATION_FOREST_PATH, Config.HOST_SCALER_PATH,
                          Config.PAYLOAD_CLASSIFIER_PATH, Config.TFIDF_VECTORIZER_PATH]:
                    if not p.exists():
                        missing.append(p.name)
                logger.warning(
                    "Missing host artifacts: %s. Initializing robust fallback heuristic pipeline.",
                    ", ".join(missing)
                )
                self.is_fallback_active = True
        except Exception as e:
            logger.error("Failed to load host model artifacts: %s. Enabling fallback mode.", e)
            self.is_fallback_active = True

    def _extract_host_features(self, data: Dict[str, Any]) -> np.ndarray:
        """Extract and order numerical host behavior features."""
        features = [
            float(data.get("processId", 1000)),
            float(data.get("parentProcessId", 1)),
            float(data.get("userId", 1000)),
            float(data.get("mountNamespace", 4026531840)),
            float(data.get("eventId", 59)),
            float(data.get("argsNum", 2)),
            float(data.get("returnValue", 0)),
            float(data.get("suspendCount", 0))
        ]
        return np.array([features], dtype=np.float32)

    def _score_host_behavior(self, features: np.ndarray, raw_data: Dict[str, Any]) -> Tuple[float, int]:
        """
        Calculates host behavioral anomaly score using Isolation Forest.
        Returns:
            normalized_score: float in [0.0, 1.0] where 1.0 is highest anomaly
            prediction: int (1 for normal, -1 for anomaly)
        """
        if not self.is_fallback_active and self.isolation_forest and self.scaler:
            try:
                scaled = self.scaler.transform(features)
                decision = float(self.isolation_forest.decision_function(scaled)[0])
                pred = int(self.isolation_forest.predict(scaled)[0])
                
                # Decision function: negative values indicate anomaly, positive indicate normal.
                # Sigmoid scaling mapped to [0, 1] range: 0 = completely normal, 1 = severe anomaly
                # At decision = 0.0, normalized_score is ~ 0.50
                normalized_score = 1.0 / (1.0 + math.exp(decision * 12.0))
                return round(float(np.clip(normalized_score, 0.0, 1.0)), 4), pred
            except Exception as e:
                logger.warning("Error during host isolation inference: %s. Falling back.", e)

        # Fallback Heuristic
        return self._fallback_host_score(raw_data)

    def _fallback_host_score(self, data: Dict[str, Any]) -> Tuple[float, int]:
        """Heuristic score if model artifact is not loaded."""
        user_id = float(data.get("userId", 1000))
        event_id = int(data.get("eventId", 59))
        return_val = float(data.get("returnValue", 0))
        args_num = float(data.get("argsNum", 2))
        pid = float(data.get("processId", 1000))
        ppid = float(data.get("parentProcessId", 1))

        anomaly_points = 0.0

        # Root execution checks
        if user_id == 0:
            anomaly_points += 0.20
        # Suspicious syscall event IDs
        if event_id in SUSPICIOUS_EVENT_IDS:
            anomaly_points += 0.25
        # Return value failure indicating probing/fuzzing/unauthorized access
        if return_val < 0:
            anomaly_points += 0.20
        # Suspicious arguments count
        if args_num > 5 or args_num == 0:
            anomaly_points += 0.15
        # Suspicious PID/PPID hierarchy
        if pid < 100 or ppid == 1:
            anomaly_points += 0.10

        anomaly_score = min(max(anomaly_points, 0.05), 0.95)
        prediction = -1 if anomaly_score >= 0.50 else 1
        return round(anomaly_score, 4), prediction

    def _score_payload(self, payload_text: str) -> float:
        """
        Calculates threat probability of command/process payload text using TF-IDF + Classifier.
        Returns:
            probability: float in [0.0, 1.0]
        """
        if not payload_text:
            return 0.02

        if not self.is_fallback_active and self.payload_classifier and self.tfidf_vectorizer:
            try:
                tfidf_vec = self.tfidf_vectorizer.transform([payload_text])
                probabilities = self.payload_classifier.predict_proba(tfidf_vec)[0]
                # Probability of malicious class (index 1)
                malicious_prob = float(probabilities[1]) if len(probabilities) > 1 else float(probabilities[0])
                return round(float(np.clip(malicious_prob, 0.0, 1.0)), 4)
            except Exception as e:
                logger.warning("Error during payload inference: %s. Falling back.", e)

        # Fallback NLP Heuristic
        return self._fallback_payload_score(payload_text)

    def _fallback_payload_score(self, payload_text: str) -> float:
        """Heuristic pattern matcher for payload threat probability."""
        score = 0.05
        text_lower = payload_text.lower()

        for pattern in SUSPICIOUS_PAYLOAD_KEYWORDS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                score += 0.35

        # Check for encoded strings or suspicious piping
        if "|" in text_lower and ("bash" in text_lower or "sh" in text_lower):
            score += 0.30
        if "http://" in text_lower or "https://" in text_lower:
            score += 0.15
        if "sudo" in text_lower or "passwd" in text_lower or "shadow" in text_lower:
            score += 0.25

        return round(float(np.clip(score, 0.02, 0.98)), 4)

    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main analysis method for Host Syscall & Payload telemetry.
        
        Composite Threat Score formula:
            Composite = (0.50 * Host Isolation Score) + (0.50 * Payload TF-IDF Threat Probability)
        """
        payload_text = str(data.get("payload_text", data.get("command_line", "")))
        features = self._extract_host_features(data)

        # 1. Host behavioral isolation score
        host_isolation_score, host_prediction = self._score_host_behavior(features, data)

        # 2. Payload threat probability
        payload_threat_prob = self._score_payload(payload_text)

        # 3. Composite Threat Score
        composite_score = round(
            (Config.HOST_ISOLATION_WEIGHT * host_isolation_score) + 
            (Config.HOST_PAYLOAD_WEIGHT * payload_threat_prob),
            4
        )

        # Determine anomaly threshold triggers
        is_anomaly = bool(
            composite_score >= Config.HOST_COMPOSITE_THRESHOLD or 
            host_prediction == -1 or 
            payload_threat_prob >= 0.70
        )

        # Categorize risk level
        if composite_score >= 0.75:
            risk_level = "CRITICAL"
        elif composite_score >= 0.60:
            risk_level = "HIGH"
        elif composite_score >= 0.35:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "module": "BETH Host Syscall & Payload Security",
            "composite_score": composite_score,
            "host_isolation_score": host_isolation_score,
            "payload_threat_probability": payload_threat_prob,
            "host_prediction": host_prediction,  # -1 = anomaly, 1 = normal
            "is_anomaly": is_anomaly,
            "risk_level": risk_level,
            "threshold": Config.HOST_COMPOSITE_THRESHOLD,
            "fallback_mode": self.is_fallback_active,
            "telemetry_summary": {
                "processId": data.get("processId", 1000),
                "parentProcessId": data.get("parentProcessId", 1),
                "userId": data.get("userId", 1000),
                "eventId": data.get("eventId", 59),
                "returnValue": data.get("returnValue", 0),
                "payload_snippet": payload_text[:120] if payload_text else "N/A"
            }
        }

    def analyze_batch(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Processes a batch DataFrame of host telemetry records (e.g. from CSV upload)."""
        results = []
        anomalies_count = 0
        composite_scores = []

        for idx, row in df.iterrows():
            row_dict = row.to_dict()
            res = self.analyze(row_dict)
            results.append({
                "row_index": idx,
                "processId": row_dict.get("processId", "N/A"),
                "userId": row_dict.get("userId", "N/A"),
                "composite_score": res["composite_score"],
                "host_isolation_score": res["host_isolation_score"],
                "payload_threat_prob": res["payload_threat_probability"],
                "risk_level": res["risk_level"],
                "is_anomaly": res["is_anomaly"]
            })
            composite_scores.append(res["composite_score"])
            if res["is_anomaly"]:
                anomalies_count += 1

        avg_composite = round(float(np.mean(composite_scores)), 4) if composite_scores else 0.0
        max_composite = round(float(np.max(composite_scores)), 4) if composite_scores else 0.0

        return {
            "total_records": len(df),
            "anomalies_detected": anomalies_count,
            "anomaly_rate_percent": round((anomalies_count / max(len(df), 1)) * 100, 2),
            "avg_composite_score": avg_composite,
            "max_composite_score": max_composite,
            "records": results[:100],  # Return up to first 100 items for frontend display
            "fallback_mode": self.is_fallback_active
        }


# Singleton instance
host_service = HostService()

