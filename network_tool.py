import socket
import threading
import queue
import time
import sys
try:
    from scapy.all import sniff, IP, TCP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

def scan_port(target, port, results):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # 1-second timeout
        result = sock.connect_ex((target, port))
        if result == 0:
            results.put(port)
        sock.close()
    except socket.error:
        pass

def port_scanner(target, start_port=1, end_port=1024, num_threads=100):
    print(f"Scanning {target} from port {start_port} to {end_port}...")
    start_time = time.time()
    
    # Resolve hostname to IP
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Error: Could not resolve hostname.")
        return
    
    results = queue.Queue()
    threads = []
    
    # Create threads for scanning
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(target_ip, port, results))
        threads.append(t)
        t.start()
        
        # Limit number of active threads
        while len([t for t in threads if t.is_alive()]) >= num_threads:
            time.sleep(0.01)
    
    # Wait for all threads to complete
    for t in threads:
        t.join()
    
    # Collect open ports
    open_ports = []
    while not results.empty():
        open_ports.append(results.get())
    open_ports.sort()
    
    # Print results
    if open_ports:
        print(f"Open ports on {target}: {open_ports}")
    else:
        print(f"No open ports found on {target} between {start_port} and {end_port}.")
    
    print(f"Scan completed in {time.time() - start_time:.2f} seconds.")

def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

def packet_sniffer_scapy():
    if not SCAPY_AVAILABLE:
        print("Error: Scapy is not installed. Install it with 'pip install scapy' or run the port scanner instead.")
        return
    
    try:
        print("Starting packet sniffer with Scapy... Press Ctrl+C to stop.")
        sniff(filter="tcp", prn=packet_callback, store=0)
    except PermissionError:
        print("Error: Run this script as Administrator and ensure Npcap is installed.")
    except KeyboardInterrupt:
        print("\nStopping packet sniffer.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("Network Tool: Choose an option")
    print("1. Port Scanner")
    print("2. Packet Sniffer (requires Scapy and Npcap)")
    choice = input("Enter 1 or 2: ").strip()
    
    if choice == "1":
        target = input("Enter the target to scan (e.g., 127.0.0.1 or scanme.nmap.org): ").strip()
        try:
            start_port = int(input("Enter start port (default 1): ") or 1)
            end_port = int(input("Enter end port (default 100): ") or 100)
            if start_port < 1 or end_port < start_port or end_port > 65535:
                print("Invalid port range. Using default 1-100.")
                start_port, end_port = 1, 100
        except ValueError:
            print("Invalid input. Using default port range 1-100.")
            start_port, end_port = 1, 100
        port_scanner(target, start_port, end_port)
    elif choice == "2":
        packet_sniffer_scapy()
    else:
        print("Invalid choice. Exiting.")
