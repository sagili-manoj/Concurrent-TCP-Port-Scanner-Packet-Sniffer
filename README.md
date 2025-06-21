# Python Network Utility: Port Scanner & Packet Sniffer

A versatile Python-based command-line tool that combines a multi-threaded TCP port scanner and a basic network packet sniffer. This project demonstrates fundamental networking concepts, concurrent programming, and interaction with network interfaces.

## Features

### 1. Multi-threaded TCP Port Scanner

* **Fast Scanning:** Utilizes multithreading to concurrently check a range of TCP ports on a target host, significantly speeding up the scanning process.
* **Hostname Resolution:** Resolves target hostnames to IP addresses.
* **Customizable Range:** Allows users to specify a custom range of ports to scan (default 1-100).
* **Timeout Handling:** Implements a timeout for connection attempts to prevent threads from hanging.
* **Error Handling:** Gracefully handles hostname resolution errors and general socket errors.

### 2. Basic Packet Sniffer (requires Scapy)

* **Real-time Packet Capture:** Captures network packets in real-time.
* **TCP Packet Filtering:** Specifically filters and displays information for TCP packets.
* **Header Parsing:** Extracts and prints source IP, destination IP, source port, and destination port from captured TCP packets.
* **Platform Compatibility:** Notes requirements for running (e.g., Administrator/root privileges, Npcap for Windows).

## Technologies Used

* **Python 3.x**
* **`socket` module:** For raw TCP socket operations in the port scanner.
* **`threading` module:** For concurrent port scanning.
* **`queue` module:** For thread-safe collection of scan results.
* **`scapy` library (optional):** For packet sniffing and parsing (requires installation).
* **`sys` module:** For system-specific parameters (though not extensively used in this version).

## Prerequisites

* Python 3.x installed.
* **For Packet Sniffer functionality:**
    * Install Scapy: `pip install scapy`
    * **Windows:** Install [Npcap](https://nmap.org/npcap/) (Scapy's dependency for Windows packet capture).
    * **Linux/macOS:** Packet sniffing often requires root privileges (`sudo`).

## How to Install and Run

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/](https://github.com/sagili-manoj/Concurrent-TCP-Port-Scanner-Packet-Sniffer)
    ```
2.  **Install Scapy (optional, for sniffer):**
    ```bash
    pip install scapy
    ```
3.  **Run the tool:**
    ```bash
    python3 network_tool.py
    ```

4.  **Follow the on-screen prompts** to choose between the Port Scanner and Packet Sniffer.

## Usage Examples

```bash
# Run the script
python network_tool.py

# Output:
# Network Tool: Choose an option
# 1. Port Scanner
# 2. Packet Sniffer (requires Scapy and Npcap)
# Enter 1 or 2: 1

# If you choose 1 (Port Scanner):
# Enter the target to scan (e.g., 127.0.0.1 or scanme.nmap.org): scanme.nmap.org
# Enter start port (default 1): 80
# Enter end port (default 100): 443

# Example Output for Port Scanner:
# Scanning scanme.nmap.org from port 80 to 443...
# Open ports on scanme.nmap.org: [80, 443]
# Scan completed in X.XX seconds.

# If you choose 2 (Packet Sniffer):
# Enter 1 or 2: 2

# Example Output for Packet Sniffer (after some network activity):
# Starting packet sniffer with Scapy... Press Ctrl+C to stop.
# TCP Packet: 192.168.1.100:54321 -> 1.2.3.4:80
# TCP Packet: 1.2.3.4:80 -> 192.168.1.100:54321
# ... (Ctrl+C to stop)
# Stopping packet sniffer.
```
