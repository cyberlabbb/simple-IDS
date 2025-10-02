import sys
import datetime
import logging
from scapy.all import sniff, IP, Raw
import joblib
import numpy as np

# ================= Logging =================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),  # Print logs to console
        logging.FileHandler("alerts.log", encoding="utf-8"),  # Save logs to file
    ],
)
logger = logging.getLogger(__name__)

# ================= Globals =================
ALERT_THRESHOLD = (
    1000  # If payload length > 1000 bytes, trigger a simple rule-based alert
)
PACKET_COUNT = 0  # Count of all sniffed packets
ALERT_COUNT = 0  # Count of triggered alerts
MODEL_PATH = "rf_payload_model.joblib"  # Path to the trained ML model
MODEL_EXPECTED_FEATURES = None  # Number of features model expects
model = None
scaler = None


# ================= Load Model =================
def load_model():
    """
    Load the trained ML model and optional scaler from a joblib file.
    The joblib file should contain a dictionary with keys like 'model' and 'scaler'.
    """
    global model, scaler, MODEL_EXPECTED_FEATURES
    try:
        saved = joblib.load(MODEL_PATH)
        model = saved.get("model")
        scaler = saved.get("scaler", None)
        logger.info(f"✅ Model loaded: {MODEL_PATH}")

        # Determine how many features the model expects
        if hasattr(model, "n_features_in_"):
            MODEL_EXPECTED_FEATURES = int(model.n_features_in_)
        elif hasattr(model, "feature_names_in_"):
            MODEL_EXPECTED_FEATURES = len(model.feature_names_in_)
        logger.info(f"Model expects {MODEL_EXPECTED_FEATURES} features")
    except Exception as e:
        logger.error(f"❌ Failed to load model: {e}")
        model = None
        scaler = None


# ================= Feature Extraction =================
def extract_features(packet):
    """
    Extract features from a network packet.
    Returns a dictionary with source IP, destination IP, protocol, and payload length.
    """
    feats = {"src_ip": "0.0.0.0", "dst_ip": "0.0.0.0", "protocol": 0, "payload_len": 0}
    if packet.haslayer(IP):
        feats["src_ip"] = packet[IP].src
        feats["dst_ip"] = packet[IP].dst
        feats["protocol"] = packet[IP].proto
    if packet.haslayer(Raw):
        feats["payload_len"] = len(packet[Raw].load)
    return feats


# ================= Packet Callback =================
def packet_callback(packet):
    """
    This function is called for each sniffed packet.
    It extracts features, applies threshold-based detection, and uses ML model if available.
    """
    global PACKET_COUNT, ALERT_COUNT
    PACKET_COUNT += 1

    # Extract features
    feats = extract_features(packet)
    src_ip = feats["src_ip"]
    dst_ip = feats["dst_ip"]
    protocol = feats["protocol"]
    payload_len = feats["payload_len"]

    # RULE-BASED DETECTION: Trigger an alert if payload is too large
    if payload_len > ALERT_THRESHOLD:
        ALERT_COUNT += 1
        logger.warning(
            f"ALERT {ALERT_COUNT}: Suspicious packet! {src_ip} -> {dst_ip}, Payload Length: {payload_len}"
        )

    # ML-BASED DETECTION: Use trained model if available
    if model is not None:
        try:
            # Prepare features for the model
            if MODEL_EXPECTED_FEATURES == 2:
                # Example: Model trained on [protocol, payload_len]
                X = np.array([[protocol, payload_len]], dtype=np.float32)
            else:
                # Example: Model trained on raw payload byte values
                payload_bytes = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""
                byte_values = list(payload_bytes)[:MODEL_EXPECTED_FEATURES]
                byte_values += [0] * (
                    MODEL_EXPECTED_FEATURES - len(byte_values)
                )  # pad with zeros
                X = np.array([byte_values], dtype=np.float32)

            # Apply scaler if available
            if scaler is not None:
                X = scaler.transform(X)

            # Predict with the model
            y_pred = model.predict(X)
            is_attack = bool(y_pred[0]) if hasattr(y_pred, "__iter__") else bool(y_pred)

            if is_attack:
                ALERT_COUNT += 1
                logger.warning(
                    f"ALERT {ALERT_COUNT}: ML detected attack! {src_ip} -> {dst_ip}, Payload Length: {payload_len}"
                )
        except Exception as e:
            logger.error(f"Prediction error: {e}")


# ================= Main =================
def main():
    """
    Main entry point.
    - Loads the ML model
    - Asks user which network interface to sniff
    - Starts sniffing until interrupted
    """
    load_model()  # Load model before starting traffic capture

    iface = input(
        "Enter the network interface to sniff (e.g., eth0, wlan0, lo): "
    ).strip()
    if not iface:
        print("No interface specified. Exiting...")
        return

    print(f"Starting packet sniffing on interface: {iface}")
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
