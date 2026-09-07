# scripts/traffic_gen.py
import subprocess, time, random

DST_IP = "192.168.50.11"

def gen_icmp(src="vpn-left"):
    count = random.randint(10, 30)
    interval = round(random.uniform(0.1, 0.5), 2)
    subprocess.run(["docker", "exec", src, "ping", "-c", str(count), "-i", str(interval), DST_IP])

def gen_web(src="vpn-left"):
    files = ["index.html", "style.css", "photo.jpg"]
    random.shuffle(files)                      # vary request order
    num_requests = random.randint(2, len(files))
    for f in files[:num_requests]:
        subprocess.run(["docker", "exec", src, "curl", "-s",
                         f"http://{DST_IP}:8080/{f}", "-o", "/dev/null"])
        time.sleep(round(random.uniform(0.1, 0.8), 2))   # human-like variable gaps
    # occasionally simulate a second "page visit" burst after a pause
    if random.random() < 0.4:
        time.sleep(round(random.uniform(1, 3), 2))
        subprocess.run(["docker", "exec", src, "curl", "-s",
                         f"http://{DST_IP}:8080/index.html", "-o", "/dev/null"])

def gen_voip(src="vpn-left", dst="vpn-right"):
    duration = random.randint(8, 20)
    bitrate = random.choice(["48k", "64k", "80k"])   # different codec-like rates
    pkt_len = random.choice([120, 160, 200])
    subprocess.run(["docker", "exec", "-d", dst, "iperf3", "-s"])
    time.sleep(1)
    subprocess.run(["docker", "exec", src, "iperf3", "-c", DST_IP, "-u",
                     "-b", bitrate, "-l", str(pkt_len), "-t", str(duration)])
    subprocess.run(["docker", "exec", dst, "pkill", "-f", "iperf3"])

def gen_video(src="vpn-left", dst="vpn-right"):
    duration = random.randint(10, 25)
    bitrate = random.choice(["3M", "5M", "8M"])       # SD/HD/4K-ish variation
    subprocess.run(["docker", "exec", "-d", dst, "iperf3", "-s"])
    time.sleep(1)
    subprocess.run(["docker", "exec", src, "iperf3", "-c", DST_IP,
                     "-b", bitrate, "-t", str(duration)])
    subprocess.run(["docker", "exec", dst, "pkill", "-f", "iperf3"])

def gen_email(src="vpn-left"):
    size_kb = random.choice([100, 500, 1000, 2000])   # varying attachment sizes
    subprocess.run(["docker", "exec", src, "bash", "-c",
                     f"dd if=/dev/urandom of=/tmp/att.bin bs=1024 count={size_kb} 2>/dev/null && "
                     f"curl -s -T /tmp/att.bin http://{DST_IP}:8080/upload -o /dev/null"])

TRAFFIC_GENERATORS = {
    "icmp": gen_icmp, "web": gen_web, "voip": gen_voip,
    "video": gen_video, "email": gen_email,
}