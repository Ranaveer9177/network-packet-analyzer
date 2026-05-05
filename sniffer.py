from scapy.all import rdpcap, IP, TCP, UDP, Raw
from collections import defaultdict

# Load packets
packets = rdpcap("capture.pcap")

# Data structures
ip_times = defaultdict(list)
port_tracker = defaultdict(set)
syn_count = defaultdict(int)

# Store HTTP data
http_data = []

# Trusted networks (CDNs / big providers)
trusted_prefixes = (
    "142.251.", "172.217.", "216.239.",   # Google
    "104.18.", "104.17.",                 # Cloudflare
    "151.101.", "199.232.",               # Fastly
)

# Process packets
for pkt in packets:
    if pkt.haslayer(IP):
        src = pkt[IP].src
        time = pkt.time

        # Skip trusted traffic
        if src.startswith(trusted_prefixes):
            continue

        ip_times[src].append(time)

        # TCP handling
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            flags = pkt[TCP].flags

            port_tracker[src].add(dport)

            # SYN detection (correct)
            if flags & 0x02:
                syn_count[src] += 1

        # UDP handling (important addition)
        if pkt.haslayer(UDP):
            dport = pkt[UDP].dport
            port_tracker[src].add(dport)

        # HTTP extraction (improved)
        if pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode(errors="ignore")
                if payload.startswith(("GET", "POST", "HTTP/")):
                    http_data.append((src, payload[:200]))
            except:
                pass

print("\n--- Analysis Report ---\n")

alerts_found = False

# Write to file
with open("report.txt", "w") as f:

    f.write("--- Analysis Report ---\n\n")

    for ip in ip_times:
        times = ip_times[ip]

        if len(times) < 10:
            continue

        duration = max(times) - min(times)
        rate = len(times) / duration if duration > 0 else 0

        unique_ports = len(port_tracker[ip])
        syns = syn_count[ip]

        # Debug info
        debug_msg = (
            f"[DEBUG] IP: {ip} | Packets: {len(times)} | "
            f"Rate: {rate:.2f} | Ports: {unique_ports} | SYN: {syns}\n"
        )
        print(debug_msg)
        f.write(debug_msg)

        alert = None

        # 🚨 Detection Logic (ordered correctly)

        # 🔴 Internal threat (highest priority inside LAN)
        if ip.startswith("192.168.") and unique_ports > 15:
            alert = f"Internal Port Scan from {ip}"

        # 🔴 SYN Flood
        elif syns > 50 and unique_ports < 10:
            alert = f"SYN Flood from {ip}"

        # 🔴 DoS Attack
        elif rate > 50 and syns > 20:
            alert = f"Likely DoS Attack from {ip}"

        # 🟠 High Traffic Anomaly
        elif rate > 150 and unique_ports <= 3:
            alert = f"High Traffic Anomaly from {ip}"

        # 🟠 Port Scanning
        elif unique_ports > 10:
            alert = f"Port Scanning from {ip}"

        # Print alerts
        if alert:
            alert_msg = (
                f"⚠️ {alert} | Rate: {rate:.2f} | "
                f"Ports: {unique_ports} | SYN: {syns}\n"
            )
            print(alert_msg)
            f.write(alert_msg)
            alerts_found = True

    # 🌐 HTTP Data Section
    if http_data:
        print("\n🌐 HTTP Traffic Found:\n")
        f.write("\nHTTP Traffic Found:\n\n")

        for src, data in http_data[:5]:
            print(f"IP: {src}")
            print(data)
            print("-" * 50)

            f.write(f"IP: {src}\n{data}\n{'-'*50}\n")

    # No alerts case
    if not alerts_found:
        print("✅ No suspicious activity detected.")
        f.write("No suspicious activity detected.\n")

print("\n📁 Report saved to report.txt")
