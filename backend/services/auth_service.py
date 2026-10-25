"""
Auth & Insider Threat Engine Service (CERT Module)
Evaluates employee authentication schedules, off-hour access, mass file reads,
and removable media usage using an Isolation Forest anomaly detector.
"""

import math
import logging
from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd
import joblib

from config import Config

logger = logging.getLogger("soc.auth_service")

# CERT Behavioral Features
AUTH_FEATURE_COLUMNS = [
    "login_hour",
    "is_weekend",
    "failed_logins",
    "usb_device_connected",
    "files_accessed",
    "data_transfer_mb",
    "privileged_commands_count",
    "after_hours_activity"
]

class AuthService:
    """Inference service for CERT Auth & Insider Threat Detection."""

    def __init__(self):
        self.model = None
        self.scaler = None
        self.is_fallback_active = False
        self._load_artifacts()

    def _load_artifacts(self) -> None:
        """Loads CERT Isolation Forest artifacts or falls back to heuristics."""
        try:
            if Config.AUTH_ANOMALY_MODEL_PATH.exists() and Config.AUTH_SCALER_PATH.exists():
                logger.info("Loading CERT Auth security artifacts from %s", Config.ARTIFACTS_PATH)
                self.model = joblib.load(Config.AUTH_ANOMALY_MODEL_PATH)
                self.scaler = joblib.load(Config.AUTH_SCALER_PATH)
                self.is_fallback_active = False
                logger.info("CERT Auth models successfully loaded.")
            else:
                missing = []
                for p in [Config.AUTH_ANOMALY_MODEL_PATH, Config.AUTH_SCALER_PATH]:
                    if not p.exists():
                        missing.append(p.name)
                logger.warning(
                    "Missing auth artifacts: %s. Initializing robust fallback heuristic pipeline.",
                    ", ".join(missing)
                )
                self.is_fallback_active = True
        except Exception as e:
            logger.error("Failed to load auth model artifacts: %s. Enabling fallback mode.", e)
            self.is_fallback_active = True

    def _extract_features(self, data: Dict[str, Any]) -> np.ndarray:
        """Extracts ordered feature vector for CERT model."""
        login_hour = float(data.get("login_hour", 10.0))
        is_weekend = float(data.get("is_weekend", 0.0))
        after_hours = 1.0 if (login_hour < 6 or login_hour > 19 or is_weekend == 1.0) else 0.0

        features = [
            login_hour,
            is_weekend,
            float(data.get("failed_logins", 0.0)),
            float(data.get("usb_device_connected", 0.0)),
            float(data.get("files_accessed", 25.0)),
            float(data.get("data_transfer_mb", 15.0)),
            float(data.get("privileged_commands_count", 0.0)),
            float(data.get("after_hours_activity", after_hours))
        ]
        return np.array([features], dtype=np.float32)

    def _fallback_auth_inference(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        High-fidelity heuristic analyzer for insider threat indicators:
        - 3 AM logins with bulk file downloads
        - USB device connected outside business hours
        - Multiple failed logins followed by privilege escalation
        """
        login_hour = float(data.get("login_hour", 10.0))
        is_weekend = float(data.get("is_weekend", 0.0))
        failed_logins = float(data.get("failed_logins", 0.0))
        usb_connected = float(data.get("usb_device_connected", 0.0))
        files_accessed = float(data.get("files_accessed", 25.0))
        data_transfer_mb = float(data.get("data_transfer_mb", 15.0))
        priv_cmds = float(data.get("privileged_commands_count", 0.0))

        risk_score = 0.05
        factors = []

        # Off-hours timing (10 PM to 5 AM)
        if login_hour <= 5 or login_hour >= 22:
            risk_score += 0.25
            factors.append("Late night/early morning access (off-hours)")
        elif login_hour < 8 or login_hour > 18:
            risk_score += 0.10
            factors.append("After-hours workplace access")

        if is_weekend == 1.0:
            risk_score += 0.15
            factors.append("Weekend facility/system login")

        # Failed logins spike
        if failed_logins >= 5:
            risk_score += 0.30
            factors.append(f"Excessive failed authentication attempts ({int(failed_logins)})")
        elif failed_logins >= 2:
            risk_score += 0.12
            factors.append(f"Multiple failed logins ({int(failed_logins)})")

        # USB device connected
        if usb_connected >= 1.0:
            risk_score += 0.25
            factors.append("Removable storage (USB mass storage) plugged in")

        # Mass file access
        if files_accessed > 200:
            risk_score += 0.35
            factors.append(f"Abnormal file access volume ({int(files_accessed)} files)")
        elif files_accessed > 80:
            risk_score += 0.15
            factors.append(f"Elevated file read activities ({int(files_accessed)} files)")

        # Massive data transfer / exfiltration
        if data_transfer_mb > 500:
            risk_score += 0.40
            factors.append(f"Mass data exfiltration volume ({data_transfer_mb:.1f} MB)")
        elif data_transfer_mb > 100:
            risk_score += 0.18
            factors.append(f"High outbound network transfer ({data_transfer_mb:.1f} MB)")

        # Privileged commands
        if priv_cmds > 3:
            risk_score += 0.30
            factors.append(f"Surge in root/privileged commands ({int(priv_cmds)})")

        normalized_score = round(float(np.clip(risk_score, 0.02, 0.99)), 4)
        is_anomaly = normalized_score >= Config.AUTH_COMPOSITE_THRESHOLD
        prediction = -1 if is_anomaly else 1
        decision_function = round(0.50 - normalized_score, 4)

        return {
            "normalized_score": normalized_score,
            "prediction": prediction,
            "decision_function": decision_function,
            "risk_factors": factors if factors else ["Behavior consistent with baseline profile"]
        }

    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main analysis method for Auth & Insider Threat telemetry.
        Returns Isolation Forest decision function score, anomaly prediction (-1 or 1),
        and normalized anomaly score [0.0, 1.0].
        """
        features = self._extract_features(data)

        if not self.is_fallback_active and self.model and self.scaler:
            try:
                scaled = self.scaler.transform(features)
                decision_function = float(self.model.decision_function(scaled)[0])
                prediction = int(self.model.predict(scaled)[0])  # -1 = Anomaly, 1 = Normal

                # Sigmoid normalization mapping:
                # Negative decision_function (outliers) maps to higher score (> 0.50)
                normalized_score = round(
                    float(np.clip(1.0 / (1.0 + math.exp(decision_function * 10.0)), 0.0, 1.0)),
                    4
                )
                is_anomaly = bool(prediction == -1 or normalized_score >= Config.AUTH_COMPOSITE_THRESHOLD)

                # Determine risk factors based on telemetry thresholds
                risk_factors = []
                if float(data.get("usb_device_connected", 0)) > 0:
                    risk_factors.append("Removable USB media connected")
                if float(data.get("data_transfer_mb", 0)) > 100:
                    risk_factors.append("High volume data transfer")
                if float(data.get("failed_logins", 0)) >= 3:
                    risk_factors.append("Multiple failed authentication attempts")
                if float(data.get("login_hour", 12)) in [0, 1, 2, 3, 4, 5, 22, 23]:
                    risk_factors.append("Off-hours session initialization")

                risk_level = "CRITICAL" if normalized_score >= 0.75 else ("HIGH" if normalized_score >= 0.60 else ("MEDIUM" if normalized_score >= 0.35 else "LOW"))

                return {
                    "module": "CERT Auth & Insider Threat Engine",
                    "user_id": data.get("user_id", "USR-4091"),
                    "decision_function": round(decision_function, 4),
                    "prediction": prediction,  # -1 = anomaly, 1 = normal
                    "anomaly_score": normalized_score,
                    "is_anomaly": is_anomaly,
                    "risk_level": risk_level,
                    "threshold": Config.AUTH_COMPOSITE_THRESHOLD,
                    "risk_factors": risk_factors if risk_factors else ["Activity fits normal user distribution"],
                    "fallback_mode": False,
                    "telemetry_summary": {
                        "login_hour": data.get("login_hour", 10),
                        "is_weekend": data.get("is_weekend", 0),
                        "failed_logins": data.get("failed_logins", 0),
                        "usb_device_connected": data.get("usb_device_connected", 0),
                        "files_accessed": data.get("files_accessed", 25),
                        "data_transfer_mb": data.get("data_transfer_mb", 15.0),
                        "privileged_commands_count": data.get("privileged_commands_count", 0)
                    }
                }
            except Exception as e:
                logger.error("Error during auth model inference: %s. Using heuristic.", e)

        # Fallback Heuristics
        fallback = self._fallback_auth_inference(data)
        normalized_score = fallback["normalized_score"]
        prediction = fallback["prediction"]
        is_anomaly = bool(prediction == -1 or normalized_score >= Config.AUTH_COMPOSITE_THRESHOLD)
        risk_level = "CRITICAL" if normalized_score >= 0.75 else ("HIGH" if normalized_score >= 0.60 else ("MEDIUM" if normalized_score >= 0.35 else "LOW"))

        return {
            "module": "CERT Auth & Insider Threat Engine",
            "user_id": data.get("user_id", "USR-4091"),
            "decision_function": fallback["decision_function"],
            "prediction": prediction,
            "anomaly_score": normalized_score,
            "is_anomaly": is_anomaly,
            "risk_level": risk_level,
            "threshold": Config.AUTH_COMPOSITE_THRESHOLD,
            "risk_factors": fallback["risk_factors"],
            "fallback_mode": True,
            "telemetry_summary": {
                "login_hour": data.get("login_hour", 10),
                "is_weekend": data.get("is_weekend", 0),
                "failed_logins": data.get("failed_logins", 0),
                "usb_device_connected": data.get("usb_device_connected", 0),
                "files_accessed": data.get("files_accessed", 25),
                "data_transfer_mb": data.get("data_transfer_mb", 15.0),
                "privileged_commands_count": data.get("privileged_commands_count", 0)
            }
        }

    def analyze_batch(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Processes a batch DataFrame of user authentication telemetry (e.g. from CSV upload)."""
        results = []
        anomalies_count = 0
        scores = []

        for idx, row in df.iterrows():
            row_dict = row.to_dict()
            res = self.analyze(row_dict)
            results.append({
                "row_index": idx,
                "user_id": row_dict.get("user_id", f"USR-{idx:04d}"),
                "login_hour": row_dict.get("login_hour", "N/A"),
                "failed_logins": row_dict.get("failed_logins", 0),
                "usb_device": row_dict.get("usb_device_connected", 0),
                "anomaly_score": res["anomaly_score"],
                "decision_function": res["decision_function"],
                "risk_level": res["risk_level"],
                "is_anomaly": res["is_anomaly"]
            })
            scores.append(res["anomaly_score"])
            if res["is_anomaly"]:
                anomalies_count += 1

        avg_score = round(float(np.mean(scores)), 4) if scores else 0.0
        max_score = round(float(np.max(scores)), 4) if scores else 0.0

        return {
            "total_records": len(df),
            "anomalies_detected": anomalies_count,
            "anomaly_rate_percent": round((anomalies_count / max(len(df), 1)) * 100, 2),
            "avg_anomaly_score": avg_score,
            "max_anomaly_score": max_score,
            "records": results[:100],
            "fallback_mode": self.is_fallback_active
        }


# Singleton instance
auth_service = AuthService()

