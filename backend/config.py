"""
AI Cybersecurity Operations Center (SOC) - Configuration
Manages environment variables, artifact paths, LLM configuration, and threat thresholds.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base Directories
BACKEND_DIR = Path(__file__).resolve().parent
ROOT_DIR = BACKEND_DIR.parent
ARTIFACTS_DIR = BACKEND_DIR / "models"

# Load .env file from backend or root directory
load_dotenv(BACKEND_DIR / ".env")
load_dotenv(ROOT_DIR / ".env")

class Config:
    """Central configuration class for the SOC Backend."""
    
    # Environment & Server
    ENV = os.getenv("FLASK_ENV", "development")
    DEBUG = os.getenv("FLASK_DEBUG", "True").lower() in ("true", "1", "yes")
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", 5000))
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")

    # Groq LLM API Configuration
    GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", 30))
    LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", 0.2))

    # Artifact File Paths
    ARTIFACTS_PATH = ARTIFACTS_DIR
    
    # Host Security Module (BETH Dataset)
    HOST_ISOLATION_FOREST_PATH = ARTIFACTS_DIR / "isolation_forest_beth.joblib"
    HOST_SCALER_PATH = ARTIFACTS_DIR / "scaler.joblib"
    PAYLOAD_CLASSIFIER_PATH = ARTIFACTS_DIR / "payload_classifier.joblib"
    TFIDF_VECTORIZER_PATH = ARTIFACTS_DIR / "tfidf_vectorizer.joblib"

    # Network Intrusion Module (NSL-KDD Dataset)
    NETWORK_IDS_MODEL_PATH = ARTIFACTS_DIR / "network_ids_model.joblib"
    NETWORK_SCALER_PATH = ARTIFACTS_DIR / "network_scaler.joblib"
    NETWORK_ENCODERS_PATH = ARTIFACTS_DIR / "network_encoders.joblib"

    # Auth & Insider Threat Module (CERT Dataset)
    AUTH_ANOMALY_MODEL_PATH = ARTIFACTS_DIR / "auth_anomaly_model.joblib"
    AUTH_SCALER_PATH = ARTIFACTS_DIR / "auth_scaler.joblib"

    # Threat Metric & Anomaly Thresholds
    HOST_COMPOSITE_THRESHOLD = float(os.getenv("HOST_COMPOSITE_THRESHOLD", 0.65))
    NETWORK_THREAT_THRESHOLD = float(os.getenv("NETWORK_THREAT_THRESHOLD", 0.50))
    AUTH_ANOMALY_THRESHOLD = -1  # Isolation Forest: -1 = Anomaly, 1 = Normal
    AUTH_COMPOSITE_THRESHOLD = float(os.getenv("AUTH_COMPOSITE_THRESHOLD", 0.65))

    # Weighting for Host Composite Threat Score
    HOST_ISOLATION_WEIGHT = 0.50
    HOST_PAYLOAD_WEIGHT = 0.50

# Ensure artifacts directory exists
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

