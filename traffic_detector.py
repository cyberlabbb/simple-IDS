#!/usr/bin/env python3
import sys
import os
import logging
import joblib
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, Raw
from typing import Dict, Any

# ================= Logging =================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("alerts.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)

# ================= Globals =================
ALERT_THRESHOLD = 1000  # If payload length > this, trigger a simple rule-based alert
PACKET_COUNT = 0
ALERT_COUNT = 0
MODEL_PATH = "rf_payload_model.joblib"  # Path to the RandomForest model
SCALER_PATH = "scaler.joblib"  # Path to the scaler (if used)
FEATURE_LEN = 1444  # Default number of bytes for payload features
HEADER_FEATURES = (
    4  # Number of header features: src_port, dst_port, protocol, payload_len
)
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
                f"Model file not found: {MODEL_PATH}. Running with rule-based detection only."
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

        # Determine expected features
        if hasattr(model, "n_features_in_"):
            expected_features = int(model.n_features_in_)
            FEATURE_LEN = expected_features - HEADER_FEATURES
        else:
            FEATURE_LEN = 1444  # Fallback default

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
    src_port = 0
    dst_port = 0
    protocol = 0
    payload_len = 0
    byte_vector = [0] * FEATURE_LEN  # Default zero vector

    if packet is None:
        return {
            "header": [src_port, dst_port, protocol, payload_len],
            "vector": byte_vector,
        }

    # Extract IP layer information
    if packet.haslayer(IP):
        protocol = int(packet[IP].proto)

    # Extract transport layer information
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # Extract Raw payload
    if packet.haslayer(Raw):
        payload_bytes = bytes(packet[Raw].load)
        payload_len = len(payload_bytes)

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
    }


# ================= Packet Callback =================
def packet_callback(packet):
    """
    Called per sniffed packet.
    Uses rule-based detection and ML model (if loaded).
    """
    global PACKET_COUNT, ALERT_COUNT, model, scaler, FEATURE_LEN
    PACKET_COUNT += 1

    feats = extract_features(packet)
    header = feats["header"]  # Header features
    vector = feats["vector"]  # Payload features

    # RULE-BASED DETECTION
    if header[3] > ALERT_THRESHOLD:  # payload_len > ALERT_THRESHOLD
        ALERT_COUNT += 1
        logger.warning(
            f"ALERT {ALERT_COUNT}: Suspicious packet (rule)! Src Port: {header[0]}, Dst Port: {header[1]}, Protocol: {header[2]}, Payload Len: {header[3]}"
        )

    # ML-BASED DETECTION (if model available)
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
                    f"ALERT {ALERT_COUNT}: ML detected attack! Src Port: {header[0]}, Dst Port: {header[1]}, Protocol: {header[2]}, Payload Len: {header[3]}"
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

    print(f"Starting packet sniffing on interface: {iface} (FEATURE_LEN={FEATURE_LEN})")
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
