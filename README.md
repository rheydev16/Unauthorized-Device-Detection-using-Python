# 🛡️ Unauthorized Device Detection in Local Network using Python

This project detects unauthorized devices connected to a local network using Python. It combines **Nmap**, **Scapy**, and a custom whitelist mechanism to identify unknown devices, log them, and optionally analyze traffic using packet capture (PCAP).

---

## 📌 Project Purpose

The goal of this project is to monitor the local network and detect unauthorized devices by comparing connected MAC addresses to a known whitelist. If an unknown MAC address is detected, its details are recorded, and its traffic is captured for further analysis.

---

## ⚙️ Tools Used

- **Python** — for scripting and automation.
- **Scapy** — to analyze and capture live packets.
- **Nmap** — to scan the network and discover connected devices.
- **Wireshark** (optional) — to review captured `.pcap` files.
- **whitelist.txt** — contains the list of authorized MAC addresses.

---

## 📁 File Structure

```text
  unauthorized-device-detector/
├── pcapfile.pcap # Packet capture file for traffic analysis
├── main.py # Main Python script
├── scan.json # Logs details of unauthorized devices
├── whitelist.txt # List of authorized MAC addresses (one per line)
├── README.md # Project documentation

```

---

## 🧠 How It Works
-Nmap scans the local network for active hosts.

-For each discovered host, the MAC address is checked against whitelist.txt.

-If the MAC address is not in the whitelist:

  -It is considered unauthorized.

  -Its IP and MAC address are saved in scan.json.

  -Scapy captures traffic from that device and saves it in pcapfile.pcap.

---  

## 🚧 Challenges Encountered
- Nmap installation issue: On Windows, Nmap wasn't recognized by Python because it wasn’t added to the system PATH.

  - ✅ Solution: Manually added the Nmap install directory to the PATH environment variable.

---

## 📚 What I Learned
- How to detect connected devices using Nmap.

- How to work with MAC address whitelists for basic network access control.

- How to automate network traffic capture using Scapy.

- How to log structured data into JSON files.

- How to troubleshoot environment issues like missing PATH variables.


  
