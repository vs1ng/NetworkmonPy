# 📡 Real-Time Network Traffic Monitor

A terminal-based real-time network monitoring tool built with Python, Scapy, and Rich.  
It displays live **incoming (IN)** and **outgoing (OUT)** traffic in two separate color-coded tables, with live updates on IPs, hostnames, countries, and suspected phishing domains.

---

## ✨ Features

- 🚦 Separates **IN** and **OUT** traffic with live counters
- 🧠 Resolves IPs to hostnames and intelligently suggests the organization
- 🌍 Detects country and shows country flag using `ipapi.co`
- 🚨 Highlights suspicious domains (e.g., with "login", "verify", etc.)
- ⚡ Built with fast multithreaded packet sniffing
- 🎨 Uses [Rich](https://github.com/Textualize/rich) for a clean terminal UI

---

## 🖼️ Screenshot

![image](https://github.com/user-attachments/assets/05905eab-3d64-4341-9bdd-74f52e827121)

---

## 🛠️ Installation

1. **Clone the repo**
   ```bash
   git clone https://github.com/vs1ng/network-monitor.git
   cd network-monitor
