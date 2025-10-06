#!/usr/bin/env python3
import sys
import os
import logging
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
FEATURE_LEN = 1444  # Default number of bytes for raw-byte vectors
DEFAULT_SHELL_PATTERNS = [".ps1", ".exe", "shellcode"]  # Patterns to detect in payload


# ================= Feature Extraction =================
# ================= Feature Extraction =================
def extract_features(packet) -> Dict[str, Any]:
    """
    Extract features from a network packet, including:
      - Header features: src_port, dst_port, protocol, payload_len
    """
    # Default values
    src_port = 0
    dst_port = 0
    protocol = 0
    payload_len = 0

    if packet is None:
        return {
            "header": [src_port, dst_port, protocol, payload_len],
        }

    # Extract IP layer information
    if packet.haslayer(IP):
        protocol = int(packet[IP].proto)

    # Extract transport layer information
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    # Extract Raw payload length
    if packet.haslayer(Raw):
        payload_len = len(bytes(packet[Raw].load))

    # Combine header features
    header_features = [src_port, dst_port, protocol, payload_len]

    return {
        "header": header_features,
    }


# ================= Packet Callback =================
def packet_callback(packet):
    """
    Called per sniffed packet.
    Filters and processes only HTTP packets (TCP port 80).
    """
    global PACKET_COUNT, ALERT_COUNT
    PACKET_COUNT += 1

    # Filter HTTP packets (TCP port 80)
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        feats = extract_features(packet)
        header = feats["header"]  # Header features

        # RULE-BASED DETECTION
        if header[3] > ALERT_THRESHOLD:  # payload_len > ALERT_THRESHOLD
            ALERT_COUNT += 1
            logger.warning(
                f"ALERT {ALERT_COUNT}: Suspicious HTTP packet! Src Port: {header[0]}, Dst Port: {header[1]}, Protocol: {header[2]}, Payload Len: {header[3]}"
            )


# ================= Main =================
def main():
    iface = input(
        "Enter the network interface to sniff (e.g., eth0, wlan0, lo): "
    ).strip()
    if not iface:
        print("No interface specified. Exiting...")
        return

    print(f"Starting packet sniffing on interface: {iface}")
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
