# 🧠 Machine Learning-Based Intrusion Detection System (IDS)

This Python script captures network packets in real-time and uses a pre-trained **machine learning model** to detect potential malicious traffic.  
It extracts payload bytes from packets, converts them into numerical feature vectors, and classifies them using a Random Forest model (`rf_payload_model.joblib`).

---

## 📋 Features

- Real-time packet sniffing using **Scapy**
- Payload byte extraction (up to 1444 bytes)
- Machine learning–based classification (RandomForest)
- Automatic logging of alerts and detection results
- Supports optional feature scaling (if a scaler is saved with the model)
- Safe handling of missing model files (runs heuristic-only mode)

---

## 🧩 Project Structure

simple-IDS/
│
├── traffic_detector.py # Main IDS script
├── rf_payload_model.joblib # Trained ML model (required)
├── traffic_alerts.log # Log file generated during runtime
├── requirements.txt # Python dependencies
└── README.md # This documentation


---

🧠 How It Works
1️⃣ Load Model

The script loads a pre-trained model from rf_payload_model.joblib.
If the file doesn’t exist, it switches to heuristic-only mode (no ML detection).

2️⃣ Capture Packets

It uses scapy.sniff() to capture real-time packets from the specified network interface.

3️⃣ Extract Features

For each packet, it:

Extracts payload bytes from the Raw layer.

Pads or truncates payloads to 1444 bytes.

Converts bytes into numerical vectors for model input.

4️⃣ Predict with ML Model

The payload vector is passed into the model for prediction.

If the prediction indicates an attack, an ALERT is logged.

5️⃣ Stop and Summarize

When stopped (Ctrl + C), it prints the total number of packets captured and total alerts detected.
