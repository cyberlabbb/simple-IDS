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
MODEL_EXPECTED_FEATURES = None  # number of features the model expects
FEATURE_LEN = 1444  # default number of bytes to use for raw-byte vectors
model = None
scaler = None


# ================= Load Model =================
def load_model():
    """
    Load the trained ML model and optional scaler from a joblib file.
    The joblib file should contain a dictionary with keys like 'model' and 'scaler'.
    """
    global model, scaler, MODEL_EXPECTED_FEATURES, FEATURE_LEN
    try:
        if not os.path.isfile(MODEL_PATH):
            logger.warning(
                f"Model file not found: {MODEL_PATH}. Running with rule-based detection only."
            )
            model = None
            scaler = None
            MODEL_EXPECTED_FEATURES = None
            FEATURE_LEN = 1444
            return

        saved = joblib.load(MODEL_PATH)
        # saved can be a dict {'model': ..., 'scaler': ...} or directly an estimator
        if isinstance(saved, dict):
            model = saved.get("model", None)
            scaler = saved.get("scaler", None)
        else:
            model = saved
            scaler = None

        logger.info(f"✅ Model loaded: {MODEL_PATH}")

        # Determine expected features
        if hasattr(model, "n_features_in_"):
            MODEL_EXPECTED_FEATURES = int(model.n_features_in_)
        elif hasattr(model, "feature_names_in_"):
            MODEL_EXPECTED_FEATURES = len(model.feature_names_in_)
        else:
            MODEL_EXPECTED_FEATURES = None

        # Decide FEATURE_LEN (used for raw-byte vectors)
        if MODEL_EXPECTED_FEATURES and MODEL_EXPECTED_FEATURES > 2:
            FEATURE_LEN = MODEL_EXPECTED_FEATURES
        else:
            FEATURE_LEN = 1444  # fallback default

        logger.info(
            f"Model expects {MODEL_EXPECTED_FEATURES} features; using FEATURE_LEN={FEATURE_LEN}"
        )
    except Exception as e:
        logger.error(f"❌ Failed to load model: {e}")
        model = None
        scaler = None
        MODEL_EXPECTED_FEATURES = None
        FEATURE_LEN = 1444


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

    The 'vector' follows the same logic as benign_pcap_to_features:
    take raw payload bytes, pad with zeros or truncate to FEATURE_LEN.
    """
    global FEATURE_LEN

    src_ip = "0.0.0.0"
    dst_ip = "0.0.0.0"
    protocol = 0
    payload_len = 0
    byte_vector = [0] * FEATURE_LEN  # default zero vector

    if packet is None:
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "payload_len": payload_len,
            "vector": byte_vector,
        }

    # IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = int(packet[IP].proto)

    # Raw payload
    if packet.haslayer(Raw):
        payload_bytes = bytes(packet[Raw].load)
        payload_len = len(payload_bytes)

        # convert to list of ints and pad/truncate to FEATURE_LEN
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
    global PACKET_COUNT, ALERT_COUNT, model, scaler, MODEL_EXPECTED_FEATURES, FEATURE_LEN
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
            # If model expects exactly 2 features, use [protocol, payload_len]
            if MODEL_EXPECTED_FEATURES == 2:
                X = np.array([[protocol, payload_len]], dtype=np.float32)
            else:
                # Use raw-byte vector. Ensure length matches expected features:
                if (
                    MODEL_EXPECTED_FEATURES is not None
                    and MODEL_EXPECTED_FEATURES != FEATURE_LEN
                ):
                    # If model expects different length, adjust:
                    if MODEL_EXPECTED_FEATURES < FEATURE_LEN:
                        X_vec = vector[:MODEL_EXPECTED_FEATURES]
                    else:
                        X_vec = vector + [0] * (MODEL_EXPECTED_FEATURES - FEATURE_LEN)
                else:
                    X_vec = vector
                X = np.array([X_vec], dtype=np.float32)

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
        # sniff indefinitely until Ctrl-C
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
