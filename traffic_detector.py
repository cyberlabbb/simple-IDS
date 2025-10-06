#!/usr/bin/env python3
import sys
import logging
from scapy.all import sniff, IP, TCP, Raw
import joblib
import numpy as np

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
PACKET_COUNT = 0
ALERT_COUNT = 0
MODEL_PATH = "rf_payload_model.joblib"
MODEL_EXPECTED_FEATURES = None
model = None
scaler = None


# ================= Load Model =================
def load_model():
    """Load trained ML model and optional scaler from joblib."""
    global model, scaler, MODEL_EXPECTED_FEATURES
    try:
        saved = joblib.load(MODEL_PATH)
        model = saved.get("model")
        scaler = saved.get("scaler", None)
        logger.info(f"✅ Model loaded: {MODEL_PATH}")

        if hasattr(model, "n_features_in_"):
            MODEL_EXPECTED_FEATURES = int(model.n_features_in_)
        elif hasattr(model, "feature_names_in_"):
            MODEL_EXPECTED_FEATURES = len(model.feature_names_in_)
        else:
            MODEL_EXPECTED_FEATURES = 2

        logger.info(f"Model expects {MODEL_EXPECTED_FEATURES} features.")
    except Exception as e:
        logger.error(f"❌ Failed to load model: {e}")
        model = None
        scaler = None


# ================= HTTP Feature Extraction =================
def extract_http_info(packet):
    """
    Extract information from HTTP packets.
    Returns dict: src_ip, dst_ip, method, host, uri, content.
    """
    if not packet.haslayer(IP) or not packet.haslayer(Raw):
        return None

    try:
        payload = packet[Raw].load.decode(errors="ignore")
        # Check if this is HTTP
        if not ("HTTP" in payload or "GET " in payload or "POST " in payload):
            return None

        lines = payload.split("\r\n")
        method, uri, host = None, None, None

        if len(lines) > 0:
            first_line = lines[0]
            if any(x in first_line for x in ["GET ", "POST ", "HEAD "]):
                parts = first_line.split(" ")
                if len(parts) >= 2:
                    method = parts[0]
                    uri = parts[1]

        for line in lines:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break

        return {
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "method": method,
            "host": host,
            "uri": uri,
            "content": payload,
        }
    except Exception:
        return None


# ================= Detection Logic =================
def detect_ps1(http_info):
    """Return True if HTTP payload contains .ps1."""
    if http_info is None:
        return False
    uri = (http_info.get("uri") or "").lower()
    content = (http_info.get("content") or "").lower()
    return ".ps1" in uri or ".ps1" in content


# ================= ML Prediction =================
def predict_attack(packet):
    """Use ML model to predict if packet is malicious."""
    global model, scaler, MODEL_EXPECTED_FEATURES

    if model is None:
        return False

    try:
        # Use Raw payload bytes as input
        payload_bytes = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""
        byte_values = list(payload_bytes)[:MODEL_EXPECTED_FEATURES]
        if len(byte_values) < MODEL_EXPECTED_FEATURES:
            byte_values += [0] * (MODEL_EXPECTED_FEATURES - len(byte_values))
        X = np.array([byte_values], dtype=np.float32)

        if scaler is not None:
            X = scaler.transform(X)

        y_pred = model.predict(X)
        return bool(y_pred[0]) if hasattr(y_pred, "__iter__") else bool(y_pred)
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return False


# ================= Packet Callback =================
def packet_callback(packet):
    global PACKET_COUNT, ALERT_COUNT
    PACKET_COUNT += 1

    http_info = extract_http_info(packet)
    if http_info is None:
        return  # skip non-HTTP traffic

    if detect_ps1(http_info):
        src, dst = http_info["src_ip"], http_info["dst_ip"]
        uri = http_info.get("uri", "")
        ALERT_COUNT += 1
        logger.warning(
            f"⚠️ ALERT {ALERT_COUNT}: Detected .ps1 in HTTP request {src} → {dst} | {uri}"
        )

        # Now apply AI model
        if predict_attack(packet):
            ALERT_COUNT += 1
            logger.warning(
                f"🤖 AI ALERT {ALERT_COUNT}: Model detected malicious HTTP packet from {src} → {dst} | {uri}"
            )


# ================= Main =================
def main():
    load_model()

    iface = input(
        "Enter the network interface to sniff (e.g., eth0, wlan0, lo): "
    ).strip()
    if not iface:
        print("No interface specified. Exiting...")
        return

    print(f"🔍 Starting HTTP sniffing on interface: {iface}")
    print("💡 Only analyzing HTTP traffic (tcp port 80)...\n")

    try:
        sniff(iface=iface, filter="tcp port 80", prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n🛑 Stopping sniffing...")
        logger.info(
            f"Stopped sniffing. Total packets: {PACKET_COUNT}, Alerts: {ALERT_COUNT}"
        )
    except Exception as e:
        logger.error(f"Error during sniffing: {e}")


if __name__ == "__main__":
    main()
