from scapy.all import *
import datetime
import requests
import threading
from flask import Flask, render_template, jsonify

# ---------------------- Flask Setup ----------------------
app = Flask(__name__)
packets = []  # Shared list for dashboard

# ---------------------- Configuration ----------------------
print("Starting Advanced Packet Analyzer with Dashboard...")
print("Press CTRL + C to stop.\n")

SUSPICIOUS_PORTS = [21, 22, 23, 445, 3389]
MAX_DASHBOARD_PACKETS = 50

total_packets = 0
tcp_count = 0
udp_count = 0
port_scan_tracker = {}

# ---------------------- Helper Functions ----------------------
def get_country(ip):
    try:
        if ip.startswith(("192.", "10.", "172.")):
            return "Private Network"
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = response.json()
        return data.get("country", "Unknown") if data.get("status") == "success" else "Unknown"
    except:
        return "Lookup Failed"

def log_packet(protocol, src_ip, src_port, dst_ip, dst_port, country):
    global packets

    # Add to dashboard
    packet_info = {
        "time": str(datetime.datetime.now()),
        "protocol": protocol,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "country": country
    }
    packets.append(packet_info)
    if len(packets) > MAX_DASHBOARD_PACKETS:
        packets.pop(0)

    # Terminal & file log
    log_entry = f"{packet_info['time']} | [{protocol}] {src_ip}:{src_port} --> {dst_ip}:{dst_port} | Country: {country}"
    print(log_entry)
    with open("traffic_log.txt", "a") as f:
        f.write(log_entry + "\n")

# ---------------------- Packet Analysis ----------------------
def analyze_packet(pkt):
    global total_packets, tcp_count, udp_count, port_scan_tracker

    if not pkt.haslayer(IP):
        return

    total_packets += 1
    ip_layer = pkt[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    if pkt.haslayer(TCP):
        tcp_count += 1
        tcp_layer = pkt[TCP]
        src_port, dst_port = tcp_layer.sport, tcp_layer.dport
        country = get_country(dst_ip)
        log_packet("TCP", src_ip, src_port, dst_ip, dst_port, country)

        # Suspicious port detection
        if dst_port in SUSPICIOUS_PORTS:
            print("🚨 WARNING: Suspicious Port Detected!")

        # Port scan detection
        if src_ip not in port_scan_tracker:
            port_scan_tracker[src_ip] = set()
        port_scan_tracker[src_ip].add(dst_port)
        if len(port_scan_tracker[src_ip]) > 10:
            print(f"🚨 Possible Port Scanning Detected from {src_ip}")

    elif pkt.haslayer(UDP):
        udp_count += 1
        udp_layer = pkt[UDP]
        src_port, dst_port = udp_layer.sport, udp_layer.dport
        country = get_country(dst_ip)
        log_packet("UDP", src_ip, src_port, dst_ip, dst_port, country)

    # Traffic summary every 10 packets
    if total_packets % 10 == 0:
        print("\n------ Traffic Summary ------")
        print(f"Total Packets: {total_packets}")
        print(f"TCP Packets: {tcp_count}")
        print(f"UDP Packets: {udp_count}")
        print("-----------------------------\n")

# ---------------------- Sniffing Thread ----------------------
stop_sniffing = False

def sniff_thread():
    sniff(prn=analyze_packet, store=False, stop_filter=lambda x: stop_sniffing)

# ---------------------- Flask Routes ----------------------
@app.route("/")
def index():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Packet Dashboard</title>
        <style>
            table { width: 100%; text-align: center; border-collapse: collapse; }
            th { background-color: #4CAF50; color: white; }
            th, td { border: 1px solid black; padding: 5px; }
        </style>
    </head>
    <body>
        <h2>Live Packet Dashboard</h2>
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Protocol</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Country</th>
                </tr>
            </thead>
            <tbody id="packet-body">
            </tbody>
        </table>

        <script>
        function fetchPackets() {
            fetch('/data')
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById("packet-body");
                    tbody.innerHTML = "";
                    data.forEach(p => {
                        tbody.innerHTML += `<tr>
                            <td>${p.time}</td>
                            <td>${p.protocol}</td>
                            <td>${p.src_ip}</td>
                            <td>${p.dst_ip}</td>
                            <td>${p.country}</td>
                        </tr>`;
                    });
                });
        }
        fetchPackets();
        setInterval(fetchPackets, 1000);
        </script>
    </body>
    </html>
    """

@app.route("/data")
def data():
    return jsonify(packets)

# ---------------------- Main Program ----------------------
if __name__ == "__main__":
    # Start sniffing in background
    t = threading.Thread(target=sniff_thread, daemon=True)
    t.start()

    # Start Flask dashboard
    app.run(debug=True)
