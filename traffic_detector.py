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
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("alerts.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)

# ================= Globals =================
ALERT_THRESHOLD = 1000  # Payload length threshold for alerts
PACKET_COUNT = 0
ALERT_COUNT = 0
MODEL_PATH = "rf_payload_model.joblib"  # Đường dẫn tới file model
MODEL_EXPECTED_FEATURES = None
model = None
scaler = None


# ================= Load Model =================
def load_model():
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
        logger.info(f"Model expects {MODEL_EXPECTED_FEATURES} features")
    except Exception as e:
        logger.error(f"❌ Failed to load model: {e}")
        model = None
        scaler = None


# ================= Packet Callback =================
def extract_features(packet):
    """Trích xuất đặc trưng từ gói tin"""
    feats = {"src_ip": "0.0.0.0", "dst_ip": "0.0.0.0", "protocol": 0, "payload_len": 0}
    if packet.haslayer(IP):
        feats["src_ip"] = packet[IP].src
        feats["dst_ip"] = packet[IP].dst
        feats["protocol"] = packet[IP].proto
    if packet.haslayer(Raw):
        feats["payload_len"] = len(packet[Raw].load)
    return feats


def packet_callback(packet):
    """Xử lý gói tin khi bắt được"""
    global PACKET_COUNT, ALERT_COUNT
    PACKET_COUNT += 1

    # Trích xuất đặc trưng
    feats = extract_features(packet)
    src_ip = feats["src_ip"]
    dst_ip = feats["dst_ip"]
    protocol = feats["protocol"]
    payload_len = feats["payload_len"]

    # Log thông tin gói tin
    logger.info(
        f"Packet {PACKET_COUNT}: {src_ip} -> {dst_ip}, Protocol: {protocol}, Payload Length: {payload_len}"
    )

    # Kiểm tra điều kiện alert dựa trên payload length
    if payload_len > ALERT_THRESHOLD:
        ALERT_COUNT += 1
        logger.warning(
            f"ALERT {ALERT_COUNT}: Suspicious packet detected! {src_ip} -> {dst_ip}, Payload Length: {payload_len}"
        )

    # Dự đoán bằng mô hình (nếu có)
    if model is not None:
        try:
            # Chuẩn bị dữ liệu đầu vào cho model
            if MODEL_EXPECTED_FEATURES == 2:
                X = np.array([[protocol, payload_len]], dtype=np.float32)
            else:
                payload_bytes = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""
                byte_values = list(payload_bytes)[:MODEL_EXPECTED_FEATURES]
                byte_values += [0] * (MODEL_EXPECTED_FEATURES - len(byte_values))
                X = np.array([byte_values], dtype=np.float32)

            # Áp dụng scaler (nếu có)
            if scaler is not None:
                X = scaler.transform(X)

            # Dự đoán
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
    load_model()  # Load model trước khi bắt traffic

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
