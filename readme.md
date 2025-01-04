# Packet Sniffer Tool

A **Python-based Packet Sniffer** tool for capturing and analyzing network packets. This tool can extract essential details such as source and destination IP addresses, protocols, and payload data. It is designed for educational purposes, ensuring the ethical use of network analysis.

---

## Features
- **Live Packet Capturing**: Capture packets in real-time.
- **Protocol Filters**: Filter packets by protocols such as TCP, UDP, or IP.
- **Data Export**: Save captured packets to a file (CSV or JSON).
- **Real-Time Graphs**: Visualize packet data trends using `matplotlib`.
- **Advanced Options**: Filter packets by specific ports or IP addresses.
- **User-Friendly GUI**: Built with `tkinter` for ease of use.

---

## Prerequisites
Ensure the following prerequisites are met:
- Python 3.7 or newer
- Administrator privileges (on Windows)
- Libraries:
  - `scapy`
  - `tkinter` (built-in)
  - `matplotlib`
  - `pandas` (for saving/exporting files)

For Windows:
- **Npcap** (required for packet sniffing): Download from [Npcap's official website](https://npcap.com/).

---

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/packet-sniffer-tool.git
   cd packet-sniffer-tool
   ```

2. Install the required Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install **Npcap** (Windows only):
   - Download and install **Npcap** from [Npcap Website](https://npcap.com/).
   - During installation, check the **"WinPcap API compatibility mode"** option.

---

## Usage
1. Run the Packet Sniffer script:
   ```bash
   python packSniffV1.py
   ```

2. **Using the GUI**:
   - Start/Stop capturing packets.
   - Apply filters (e.g., `tcp`, `udp`).
   - View packet details in the interface.
   - Save captured data to CSV or JSON format.
   - Generate real-time graphs of captured data trends.

---

## How to Apply Filters
The following filters can be used:
- `tcp`: Capture only TCP packets.
- `udp`: Capture only UDP packets.
- `port 80`: Capture HTTP traffic.
- `host 192.168.0.1`: Capture traffic involving a specific host.

**Example**: To capture only TCP traffic:
- Enter `tcp` in the filter field.

---

## Troubleshooting

### `RuntimeError: Sniffing and sending packets is not available at layer 2`
- Install **Npcap** on Windows.
- Run the script with administrator privileges.

### `ModuleNotFoundError` for libraries
- Ensure all required libraries are installed by running:
  ```bash
  pip install -r requirements.txt
  ```

### `Tkinter not found`
- Reinstall Python with `tkinter` support:
  - For Windows: Enable the **tcl/tk and IDLE** option during installation.
  - For Linux: Install using:
    ```bash
    sudo apt-get install python3-tk
    ```

---

## Example Screenshots
Add screenshots of:
- The GUI interface.
- Real-time graphs.
- Filtered packet data.

---

## Acknowledgments
- Built with Python's **Scapy** for packet analysis.
- GUI created using **Tkinter**.
- Graph plotting by **Matplotlib**.

---

## Disclaimer
This tool is strictly for educational purposes. **Do not use this for unauthorized network monitoring or any activity that violates privacy or laws.**

---

## License
This project is licensed under the [MIT License](LICENSE).

---

## Contribution
Pull requests are welcome! For significant changes, please open an issue to discuss your ideas.

# Project Overview

Here is a screenshot of the application:

![App Screenshot](images/screenshot.png)


### **To Do Next**
- Replace placeholder sections (e.g., screenshots or repository URL) with relevant information specific to your project.
- Include a `requirements.txt` file listing all required Python libraries, e.g.:
  ```plaintext
  scapy
  matplotlib
  pandas
  pyshark
  ```

Let me know if you'd like assistance with these steps! 🚀
