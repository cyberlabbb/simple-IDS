#!/usr/bin/env python3
import sys
import os
import logging
import joblib
import numpy as np
from scapy.all import sniff, IP, Raw, TCP, UDP
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
MODEL_PATH = "rf_payload_model.joblib"
FEATURE_LEN = 1444  # Fixed payload length for feature extraction
model = None
scaler = None


# ================= Load Model =================
def load_model():
    """
    Load the trained Random Forest model and optional scaler from a joblib file.
    """
    global model, scaler
    try:
        if not os.path.isfile(MODEL_PATH):
            logger.error(f"Model file not found: {MODEL_PATH}. Exiting...")
            sys.exit(1)

        saved = joblib.load(MODEL_PATH)
        # Check if the saved object is a dictionary containing the model and scaler
        if isinstance(saved, dict):
            model = saved.get("model", None)
            scaler = saved.get("scaler", None)
        else:
            model = saved
            scaler = None

        logger.info(f"✅ Model loaded: {MODEL_PATH}")
    except Exception as e:
        logger.error(f"❌ Failed to load model: {e}")
        sys.exit(1)


# ================= Feature Extraction =================
def extract_features(packet) -> Dict[str, Any]:
    """
    Extract features from a network packet and return:
      {
        "src_ip": str,
        "dst_ip": str,
        "protocol": int,
        "payload_len": int,
        "vector": List[int]  # fixed-length byte vector (len = FEATURE_LEN)
      }

    The 'vector' is a fixed-length byte vector derived from the packet payload.
    """
    src_ip = "0.0.0.0"
    dst_ip = "0.0.0.0"
    protocol = 0
    payload_len = 0
    byte_vector = [0] * FEATURE_LEN  # Default zero vector

    if packet is None:
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "payload_len": payload_len,
            "vector": byte_vector,
        }

    # Extract IP layer information
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = int(packet[IP].proto)

    # Extract Raw payload
    if packet.haslayer(Raw):
        payload_bytes = bytes(packet[Raw].load)
        payload_len = len(payload_bytes)

        # Convert to list of ints and pad/truncate to FEATURE_LEN
        byte_list = list(payload_bytes[:FEATURE_LEN])
        if len(byte_list) < FEATURE_LEN:
            byte_list.extend([0] * (FEATURE_LEN - len(byte_list)))
        byte_vector = byte_list

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "payload_len": payload_len,
        "vector": byte_vector,
    }


# ================= Packet Callback =================
def packet_callback(packet):
    """
    Called per sniffed packet.
    Uses rule-based detection and ML model (if loaded).
    """
    global PACKET_COUNT, ALERT_COUNT, model, scaler
    PACKET_COUNT += 1

    feats = extract_features(packet)
    src_ip = feats["src_ip"]
    dst_ip = feats["dst_ip"]
    protocol = feats["protocol"]
    payload_len = feats["payload_len"]
    vector = feats["vector"]  # list[int] length FEATURE_LEN

    # RULE-BASED DETECTION
    if payload_len > ALERT_THRESHOLD:
        ALERT_COUNT += 1
        logger.warning(
            f"ALERT {ALERT_COUNT}: Suspicious packet (rule)! {src_ip} -> {dst_ip}, proto={protocol}, payload_len={payload_len}"
        )

    # ML-BASED DETECTION (if model available)
    if model is not None:
        try:
            X = np.array([vector], dtype=np.float32)

            # Apply scaler if provided
            if scaler is not None:
                X = scaler.transform(X)

            # Make prediction
            y_pred = model.predict(X)
            is_attack = bool(y_pred[0]) if hasattr(y_pred, "__iter__") else bool(y_pred)

            if is_attack:
                ALERT_COUNT += 1
                logger.warning(
                    f"ALERT {ALERT_COUNT}: ML detected attack! {src_ip} -> {dst_ip}, proto={protocol}, payload_len={payload_len}"
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
