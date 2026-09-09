# scripts/traffic_gen.py
import subprocess, time, random

DST_IP = "192.168.50.11"

def gen_icmp(src="vpn-left"):
    count = random.randint(10, 60)
    interval = round(random.uniform(0.05, 0.8), 2)
    subprocess.run(["docker", "exec", src, "ping", "-c", str(count), "-i", str(interval), DST_IP])

def gen_web(src="vpn-left"):
    files = ["index.html", "style.css", "photo.jpg"]
    random.shuffle(files)
    num_requests = random.randint(3, 12)
    for _ in range(num_requests):
        f = random.choice(files)
        subprocess.run(["docker", "exec", src, "curl", "-s",
                         f"http://{DST_IP}:8080/{f}", "-o", "/dev/null"])
        time.sleep(round(random.uniform(0.05, 1.8), 2))
    # occasionally simulate a second browsing burst after an idle think-time
    if random.random() < 0.5:
        time.sleep(round(random.uniform(1.5, 4.0), 2))
        subprocess.run(["docker", "exec", src, "curl", "-s",
                         f"http://{DST_IP}:8080/index.html", "-o", "/dev/null"])

def gen_voip(src="vpn-left", dst="vpn-right"):
    duration = random.randint(6, 35)
    kbps = random.randint(24, 128)
    bitrate = f"{kbps}k"
    pkt_len = random.randint(80, 260)
    subprocess.run(["docker", "exec", "-d", dst, "iperf3", "-s"])
    time.sleep(1)
    subprocess.run(["docker", "exec", src, "iperf3", "-c", DST_IP, "-u",
                     "-b", bitrate, "-l", str(pkt_len), "-t", str(duration)])
    subprocess.run(["docker", "exec", dst, "pkill", "-f", "iperf3"])

def gen_video(src="vpn-left", dst="vpn-right"):
    duration = random.randint(8, 45)
    mbps = random.randint(2, 16)
    bitrate = f"{mbps}M"
    subprocess.run(["docker", "exec", "-d", dst, "iperf3", "-s"])
    time.sleep(1)
    subprocess.run(["docker", "exec", src, "iperf3", "-c", DST_IP,
                     "-b", bitrate, "-t", str(duration)])
    subprocess.run(["docker", "exec", dst, "pkill", "-f", "iperf3"])

def gen_email(src="vpn-left"):
    size_kb = random.randint(40, 1200)
    subprocess.run([
        "docker", "exec", src, "python3", "-c",
        f"""
import urllib.request, os, time
data = os.urandom({size_kb} * 1024)
try:
    req = urllib.request.Request('http://{DST_IP}:8080/', data=data, method='POST')
    urllib.request.urlopen(req, timeout=12)
except Exception:
    pass
"""
    ])

def gen_whatsapp(src="vpn-left"):
    num_messages = random.randint(6, 25)
    for _ in range(num_messages):
        msg_size = random.choice([80, 140, 220, 360, 520, 950, 1400])
        subprocess.run([
            "docker", "exec", src, "python3", "-c",
            f"""
import urllib.request, os
data = os.urandom({msg_size})
try:
    req = urllib.request.Request('http://{DST_IP}:8080/?chat=wa', data=data, method='POST')
    urllib.request.urlopen(req, timeout=4)
except Exception:
    pass
"""
        ])
        time.sleep(round(random.uniform(0.15, 1.8), 2))

# ==============================================================================
# Realistic Anomaly & Cyber Threat Flow Generators
# ==============================================================================

def gen_exfiltration(src="vpn-left"):
    """
    Data Exfiltration Anomaly:
    Continuous high-throughput unidirectional data dumping over the VPN tunnel.
    Direction ratio approaches ~0.98, high bytes_per_sec, distinct packet chunking.
    """
    size_mb = random.randint(4, 18)
    subprocess.run([
        "docker", "exec", src, "python3", "-c",
        f"""
import urllib.request, os
data = os.urandom({size_mb} * 1024 * 1024)
try:
    req = urllib.request.Request('http://{DST_IP}:8080/upload_archive', data=data, method='POST')
    urllib.request.urlopen(req, timeout=20)
except Exception:
    pass
"""
    ])

def gen_portscan(src="vpn-left"):
    """
    Internal Reconnaissance Anomaly (Port Scan):
    Rapid series of small TCP probes targeting multiple internal ports with near-zero replies.
    """
    ports = random.sample(range(20, 1024), random.randint(25, 60))
    ports_str = ",".join(map(str, ports))
    subprocess.run([
        "docker", "exec", src, "python3", "-c",
        f"""
import socket
for p in [{ports_str}]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.04)
    try:
        s.connect(('{DST_IP}', p))
    except Exception:
        pass
    finally:
        s.close()
"""
    ])

def gen_c2_beacon(src="vpn-left"):
    """
    Command & Control (C2) Heartbeat Beaconing:
    Periodic fixed micro-pulses (near zero IAT variance) with tiny payloads.
    """
    beacons = random.randint(8, 20)
    interval = round(random.uniform(1.2, 3.5), 2)
    payload_len = random.choice([64, 96, 128])
    subprocess.run([
        "docker", "exec", src, "python3", "-c",
        f"""
import urllib.request, time, os
for _ in range({beacons}):
    try:
        req = urllib.request.Request('http://{DST_IP}:8080/beacon', data=os.urandom({payload_len}), method='POST')
        urllib.request.urlopen(req, timeout=2)
    except Exception:
        pass
    time.sleep({interval})
"""
    ])

def gen_dos_flood(src="vpn-left", dst="vpn-right"):
    """
    Tunnel Volumetric Flooding / DoS Anomaly:
    High-bandwidth saturation with near-zero inter-arrival time.
    """
    duration = random.randint(6, 15)
    subprocess.run(["docker", "exec", "-d", dst, "iperf3", "-s"])
    time.sleep(1)
    subprocess.run(["docker", "exec", src, "iperf3", "-c", DST_IP, "-u",
                     "-b", "50M", "-t", str(duration)])
    subprocess.run(["docker", "exec", dst, "pkill", "-f", "iperf3"])


TRAFFIC_GENERATORS = {
    # Normal Baseline Classes
    "icmp": gen_icmp,
    "web": gen_web,
    "voip": gen_voip,
    "video": gen_video,
    "email": gen_email,
    "whatsapp": gen_whatsapp,
    # Anomaly / Threat Classes
    "exfiltration": gen_exfiltration,
    "portscan": gen_portscan,
    "c2_beacon": gen_c2_beacon,
    "dos_flood": gen_dos_flood,
}
