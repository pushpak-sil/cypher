import base64
import json
import os
import subprocess
import sys
import time
from jinja2 import Environment, FileSystemLoader

# Set working directory to repository root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(PROJECT_ROOT)

sys.path.append(os.path.join(PROJECT_ROOT, "scripts"))
from traffic_gen import TRAFFIC_GENERATORS

env = Environment(loader=FileSystemLoader("templates"))
template = env.get_template("ipsec.conf.j2")

CIPHER_PROFILES = {
    "aes128_cbc": {"esp": "aes128-sha256", "ike": "aes128-sha256"},
    "aes256_cbc": {"esp": "aes256-sha256", "ike": "aes256-sha256"},
    "aes256_gcm": {"esp": "aes256gcm16", "ike": "aes256-sha256"},
    "aes256_cbc_hmac": {"esp": "aes256-sha1", "ike": "aes256-sha1"},
}


def build_proposals(cfg):
  base = CIPHER_PROFILES.get(
      cfg["cipher_profile"], {"esp": "aes256-sha256", "ike": "aes256-sha256"}
  )
  dh = cfg["dh_group"]
  cfg["ike_proposal"] = f"{base['ike']}-{dh}"
  # strongSwan accepts 'aes256gcm16-modp2048' directly for AEAD with PFS
  cfg["esp_proposal"] = f"{base['esp']}-{dh}" if cfg.get("pfs") else base["esp"]


def push_to_container(host, content):
  b64_data = base64.b64encode(content.encode("utf-8")).decode("ascii")
  res = subprocess.run(
      [
          "docker",
          "exec",
          host,
          "sh",
          "-c",
          f"echo {b64_data} | base64 -d > /etc/ipsec.conf",
      ],
      capture_output=True,
      text=True,
  )
  if res.returncode != 0:
    print(f"[-] Failed to update config on {host}: {res.stderr.strip()}")


def push_config(cfg):
  os.makedirs("configs/generated", exist_ok=True)
  build_proposals(cfg)

  # Configure vpn-left (192.168.50.10)
  left_cfg = dict(
      cfg,
      local_ip="192.168.50.10",
      local_id="left",
      remote_ip="192.168.50.11",
      remote_id="right",
  )
  conf_left = template.render(**left_cfg)
  with open("configs/generated/left.conf", "w", newline="\n") as f:
    f.write(conf_left + "\n")
  push_to_container("vpn-left", conf_left + "\n")

  # Configure vpn-right (192.168.50.11)
  right_cfg = dict(
      cfg,
      local_ip="192.168.50.11",
      local_id="right",
      remote_ip="192.168.50.10",
      remote_id="left",
  )
  conf_right = template.render(**right_cfg)
  with open("configs/generated/right.conf", "w", newline="\n") as f:
    f.write(conf_right + "\n")
  push_to_container("vpn-right", conf_right + "\n")


def reload_ipsec():
  """Dynamically reloads configurations without stopping or restarting the charon daemon."""
  for host in ["vpn-left", "vpn-right"]:
    res = subprocess.run(
        ["docker", "exec", host, "ipsec", "reload"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if "starter is not running" in res.stderr:
      subprocess.run(
          ["docker", "exec", host, "ipsec", "start"],
          stdout=subprocess.DEVNULL,
          stderr=subprocess.DEVNULL,
      )
  time.sleep(1)


def start_capture(host, pcap_path):
  subprocess.run(
      [
          "docker",
          "exec",
          "-d",
          host,
          "tcpdump",
          "-U",
          "-i",
          "eth0",
          "-w",
          pcap_path,
      ],
      stdout=subprocess.DEVNULL,
      stderr=subprocess.DEVNULL,
  )
  time.sleep(1)


def stop_capture(host):
  subprocess.run(
      ["docker", "exec", host, "pkill", "-2", "-f", "tcpdump"],
      stdout=subprocess.DEVNULL,
      stderr=subprocess.DEVNULL,
  )
  time.sleep(1)


def bring_up():
  """Initiates the tunnel and returns output for diagnostic logging."""
  try:
    res = subprocess.run(
        ["docker", "exec", "vpn-left", "ipsec", "up", "test-conn"],
        capture_output=True,
        text=True,
        timeout=12,
    )
    return res.stdout + res.stderr
  except subprocess.TimeoutExpired:
    return "ipsec up timed out after 12 seconds"


def verify():
  try:
    res = subprocess.run(
        ["docker", "exec", "vpn-left", "ipsec", "statusall"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    output = res.stdout + res.stderr
    return "ESTABLISHED" in output, output
  except subprocess.TimeoutExpired:
    return False, "ipsec statusall timed out"


def tear_down():
  subprocess.run(
      ["docker", "exec", "vpn-left", "ipsec", "down", "test-conn"],
      stdout=subprocess.DEVNULL,
      stderr=subprocess.DEVNULL,
  )


def run_all(matrix):
  os.makedirs("captures", exist_ok=True)
  manifest = []

  for cfg in matrix:
    run_id = cfg["run_id"]
    pcap_container_path = f"/captures/{run_id}.pcap"
    pcap_host_path = f"captures/{run_id}.pcap"

    print(
        f"[{run_id}] {cfg['cipher_profile']} / {cfg['mode']} /"
        f" traffic={cfg['traffic_type']}"
    )

    push_config(cfg)
    reload_ipsec()

    # Capture packets before initiating negotiation
    start_capture("vpn-left", pcap_container_path)

    up_output = bring_up()
    ok, diag = verify()
    cfg["tunnel_established"] = ok

    if ok:
      print("  [+] Tunnel ESTABLISHED. Generating traffic...")
      traffic_fn = TRAFFIC_GENERATORS.get(cfg["traffic_type"])
      if traffic_fn:
        traffic_fn()
    else:
      print("  [!] WARNING: Tunnel failed to establish.")
      # Display why the negotiation failed from ipsec up
      err_lines = [line.strip() for line in up_output.splitlines() if line.strip()]
      for line in err_lines[-3:]:
        print(f"      {line}")

    time.sleep(1)
    stop_capture("vpn-left")
    tear_down()

    cfg["pcap_file"] = pcap_host_path
    manifest.append(cfg)

  with open("manifest.json", "w", newline="\n") as f:
    json.dump(manifest, f, indent=2)

  print(f"\n[+] Finished {len(manifest)} runs. Manifest saved to manifest.json")


if __name__ == "__main__":
  matrix_path = "configs/matrix.json"
  if not os.path.exists(matrix_path):
    print(f"[-] Missing {matrix_path}. Run generate_matrix.py first.")
    sys.exit(1)

  with open(matrix_path) as f:
    matrix = json.load(f)
  run_all(matrix)