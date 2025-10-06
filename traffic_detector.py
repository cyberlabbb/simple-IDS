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
HEADER_FEATURES = 6  # Number of header features
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

        logger.info(f"✅ Model loaded: {MODEL_PATH}")

        # Adjust FEATURE_LEN based on model expectations
        if hasattr(model, "n_features_in_"):
            expected_features = int(model.n_features_in_)
            FEATURE_LEN = expected_features - HEADER_FEATURES
        else:
            FEATURE_LEN = 1444  # Default fallback

        logger.info(f"Using FEATURE_LEN={FEATURE_LEN}")
    except Exception as e:
        logger.error(f"❌ Failed to load model: {e}")
        model = None
        scaler = None


# ================= Feature Extraction =================
def extract_features(packet) -> Dict[str, Any]:
    """
    Extract features from a network packet, including:
      - Header features: src_port, dst_port, protocol, payload_len
      - Payload features: fixed-length byte vector (len = FEATURE_LEN)
    """
    global FEATURE_LEN

    # Default values
    src_ip = "0.0.0.0"
    dst_ip = "0.0.0.0"
    src_port = 0
    dst_port = 0
    protocol = 0
    payload_len = 0
    byte_vector = [0] * FEATURE_LEN  # Default zero vector
    payload_content = ""

    if packet is None:
        return {
            "header": [src_port, dst_port, protocol, payload_len],
            "vector": byte_vector,
            "payload_content": payload_content,
        }

    # Extract IP layer information
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = int(packet[IP].proto)

    # Extract transport layer information
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    # Extract Raw payload
    if packet.haslayer(Raw):
        payload_bytes = bytes(packet[Raw].load)
        payload_len = len(payload_bytes)
        payload_content = payload_bytes.decode("utf-8", errors="ignore")

        # Convert to list of ints and pad/truncate to FEATURE_LEN
        byte_list = list(payload_bytes[:FEATURE_LEN])
        if len(byte_list) < FEATURE_LEN:
            byte_list.extend([0] * (FEATURE_LEN - len(byte_list)))
        byte_vector = byte_list

    # Combine header features
    header_features = [src_port, dst_port, protocol, payload_len]

    return {
        "header": header_features,
        "vector": byte_vector,
        "payload_content": payload_content,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
    }


# ================= Packet Callback =================
def packet_callback(packet):
    """
    Called per sniffed packet.
    Uses heuristic detection and ML model (if loaded) to classify packets.
    """
    global PACKET_COUNT, ALERT_COUNT, model, scaler
    PACKET_COUNT += 1

    feats = extract_features(packet)
    header = feats["header"]  # Header features
    vector = feats["vector"]  # Payload features
    payload_content = feats["payload_content"]  # Extracted payload content
    src_ip = feats["src_ip"]
    dst_ip = feats["dst_ip"]

    # HEURISTIC DETECTION
    # 1. Shellcode pattern matching
    for pattern in DEFAULT_SHELL_PATTERNS:
        if re.search(pattern, payload_content, re.IGNORECASE):
            ALERT_COUNT += 1
            logger.warning(
                f"ALERT {ALERT_COUNT}: Shellcode pattern detected! Pattern: '{pattern}', Src IP: {src_ip}, Dst IP: {dst_ip}"
            )
            return

    # 2. Blacklist matching
    if dst_ip in DEFAULT_BLACKLIST:
        ALERT_COUNT += 1
        logger.warning(
            f"ALERT {ALERT_COUNT}: Blacklisted destination detected! Dst IP: {dst_ip}, Src IP: {src_ip}"
        )
        return

    # ML-BASED DETECTION
    if model is not None:
        try:
            # Combine header and payload features
            X = np.array([header + vector], dtype=np.float32)

            # Apply scaler if provided
            if scaler is not None:
                X = scaler.transform(X)

            # Make prediction
            y_pred = model.predict(X)
            is_attack = bool(y_pred[0]) if hasattr(y_pred, "__iter__") else bool(y_pred)

            if is_attack:
                ALERT_COUNT += 1
                logger.warning(
                    f"ALERT {ALERT_COUNT}: ML detected attack! Src IP: {src_ip}, Dst IP: {dst_ip}, Protocol: {header[2]}"
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
        # Sniff indefinitely until Ctrl-C
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