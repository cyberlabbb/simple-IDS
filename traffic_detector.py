#!/usr/bin/env python3
import sys
import os
import logging
import joblib
import numpy as np
from scapy.all import sniff, IP, TCP, Raw
from typing import Dict, Any
import re

# ================= Logging =================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("traffic_alerts.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)

# ================= Globals =================
PACKET_COUNT = 0
ALERT_COUNT = 0
MODEL_PATH = "rf_payload_model.joblib"  # Path to the trained model
FEATURE_LEN = 1444  # Default number of bytes for payload vector
DEFAULT_SHELL_PATTERNS = [".ps1", ".exe", ".dll"]  # Patterns to detect in payload
DEFAULT_BLACKLIST = ["192.168.90.105", "192.168.90.112"]  # Blacklisted IPs
model = None
scaler = None


# ================= Load Model =================
def load_model():
    """
    Load the trained ML model and optional scaler from a joblib file.
    """
    global model, scaler, FEATURE_LEN
    try:
        if not os.path.isfile(MODEL_PATH):
            logger.warning(
                f"Model file not found: {MODEL_PATH}. Running with heuristic detection only."
            )
            model = None
            scaler = None
            return

        saved = joblib.load(MODEL_PATH)
        if isinstance(saved, dict):
            model = saved.get("model", None)
            scaler = saved.get("scaler", None)
        else:
            model = saved
            scaler = None

        logger.info(f"✅ Model loaded successfully from: {MODEL_PATH}")

        # Adjust FEATURE_LEN dynamically based on model structure
        if hasattr(model, "n_features_in_"):
            FEATURE_LEN = int(model.n_features_in_)
        else:
            FEATURE_LEN = 1444  # Fallback default

        logger.info(f"Expected model input size: {FEATURE_LEN} features")
    except Exception as e:
        logger.error(f"❌ Failed to load model: {e}")
        model = None
        scaler = None


# ================= Feature Extraction =================
def extract_features(packet) -> Dict[str, Any]:
    """
    Extracts payload bytes from packets and converts them into a fixed-length vector.
    """
    global FEATURE_LEN

    src_ip = "0.0.0.0"
    dst_ip = "0.0.0.0"
    protocol = 0
    payload_content = ""
    byte_vector = [0] * FEATURE_LEN  # Default zero vector

    if packet is None:
        return {
            "vector": byte_vector,
            "payload_content": payload_content,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
        }

    # Extract IP info
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = int(packet[IP].proto)

    # Extract payload
    if packet.haslayer(Raw):
        payload_bytes = bytes(packet[Raw].load)
        payload_content = payload_bytes.decode("utf-8", errors="ignore")

        byte_list = list(payload_bytes[:FEATURE_LEN])
        if len(byte_list) < FEATURE_LEN:
            byte_list.extend([0] * (FEATURE_LEN - len(byte_list)))
        byte_vector = byte_list

    return {
        "vector": byte_vector,
        "payload_content": payload_content,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
    }


# ================= Packet Callback =================
def packet_callback(packet):
    """
    Called per sniffed packet.
    Performs heuristic and ML-based anomaly detection.
    """
    global PACKET_COUNT, ALERT_COUNT, model, scaler
    PACKET_COUNT += 1

    feats = extract_features(packet)
    vector = feats["vector"]
    payload_content = feats["payload_content"]
    src_ip = feats["src_ip"]
    dst_ip = feats["dst_ip"]
    protocol = feats["protocol"]

    # ---- Heuristic Detection ----
    # 1. Detect suspicious patterns
    for pattern in DEFAULT_SHELL_PATTERNS:
        if re.search(pattern, payload_content, re.IGNORECASE):
            ALERT_COUNT += 1
            logger.warning(
                f"ALERT {ALERT_COUNT}: Shellcode pattern detected! Pattern: '{pattern}', Src IP: {src_ip}, Dst IP: {dst_ip}"
            )
            return

    # 2. Blacklist detection
    if dst_ip in DEFAULT_BLACKLIST:
        ALERT_COUNT += 1
        logger.warning(
            f"ALERT {ALERT_COUNT}: Blacklisted destination detected! Dst IP: {dst_ip}, Src IP: {src_ip}"
        )
        return

    # ---- ML Detection ----
    if model is not None:
        try:
            X = np.array([vector], dtype=np.float32)

            # Validate input size
            if X.shape[1] != model.n_features_in_:
                logger.error(
                    f"⚠️ Feature length mismatch: got {X.shape[1]}, expected {model.n_features_in_}"
                )
                return

            if scaler is not None:
                X = scaler.transform(X)

            y_pred = model.predict(X)
            is_attack = bool(y_pred[0]) if hasattr(y_pred, "__iter__") else bool(y_pred)

            if is_attack:
                ALERT_COUNT += 1
                logger.warning(
                    f"ALERT {ALERT_COUNT}: 🚨 ML detected attack! Src IP: {src_ip}, Dst IP: {dst_ip}, Protocol: {protocol}"
                )
        except Exception as e:
            logger.error(f"Prediction error: {e}")


# ================= Main =================
def main():
    load_model()

    iface = input(
        "Enter the network interface to sniff (e.g., eth0, wlan0, lo): "
    ).strip()
    if not iface:
        print("No interface specified. Exiting...")
        return

    print(f"Starting real-time packet sniffing on interface: {iface}")
    try:
        sniff(iface=iface, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\nStopping packet sniffing...")
        logger.info(
            f"Stopped sniffing. Total packets: {PACKET_COUNT}, Alerts: {ALERT_COUNT}"
        )
    except Exception as e:
        logger.error(f"Error during sniffing: {e}")


if __name__ == "__main__":
    main()
