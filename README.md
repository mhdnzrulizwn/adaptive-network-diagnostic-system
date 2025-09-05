# Adaptive Network Diagnostic System

This project is a **Final Year Project (FYP)** that develops an adaptive network diagnostic system combining **rule-based analysis** and an **enhanced autoencoder** to detect and classify anomalies in clustered LAN environments. The system is designed for institutional networks, providing **automated, accurate, and user-friendly diagnostics** without requiring deep technical expertise.

---

## 🔹 Features
- **Hybrid Diagnostic Engine**
  - Rule-based engine with dynamic threshold management  
  - TensorFlow-based enhanced autoencoder for anomaly detection  
  - Decision fusion mechanism (70% rule-based, 30% ML)  

- **Agent Module**
  - Collects system metrics, faults, processes, and ML insights  
  - Runs IP diagnostics (DHCP, DNS, connectivity checks)  
  - Sends data using **multi-protocol fallback**:  
    1. HTTP (primary)  
    2. UDP Broadcast (fallback)  
    3. Layer 2 Ethernet (last resort)  

- **Server Module**
  - Flask-based central dashboard for monitoring  
  - SQLite database to store agents, metrics, faults, ML insights, IP diagnostics, and events  
  - Handles agent communication via HTTP, UDP, and Layer 2 Ethernet  
  - Real-time dashboards with Plotly visualizations  
  - Event logging and troubleshooting insights  

---

## 🔹 Project Structure
adaptive-network-diagnostic-system/
│
├── agent.py # Agent program
├── server.py # Server program (Flask + DB + dashboard)
├── requirements.txt # Python dependencies
└── README.md # Project documentations

---

## 🔹 Installation
### Requirements
- Python 3.8+
- Install dependencies:
```bash
pip install -r requirements.txt

---

## 🔹 Usage
python server.py
Runs on http://localhost:8080

python agent.py
Local dashboard available at http://localhost:5000

---

## 🔹 Configuration
Settings are stored in agent_config.ini:
[AGENT]
enabled = true
server_url = http://localhost:8080
send_interval = 30
enable_layer2 = true
broadcast_port = 9999

[DATA]
send_metrics = true
send_faults = true
send_processes = true
send_ml_insights = true
send_ip_diagnostics = true

---

##🔹 Example Workflow
1. Agent collects system metrics and diagnostics.
2. Sends data to server via HTTP → if it fails, falls back to UDP → if that fails, uses Layer 2.
3. Server aggregates data and applies hybrid diagnostic logic.
4. Results and alerts are stored in SQLite and displayed on the dashboard.

---

##🔹 Tech Stack

Python
TensorFlow / Keras – Autoencoder model
Flask – Web dashboard (server)
SQLite – Database
Plotly – Data visualization
Scapy – Layer 2 packet handling
psutil / netifaces – System & network metrics
scikit-learn – Data preprocessing

---

##🔹 License
This project is licensed under the MIT License (see LICENSE file). 
Developed as part of a Final Year Project at Universiti Teknikal Malaysia Melaka (UTeM).

This project is licensed under the MIT License (see LICENSE file). 
Developed as part of a Final Year Project at Universiti Teknikal Malaysia Melaka (UTeM).
