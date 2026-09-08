import base64
import json
import os
import subprocess
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(PROJECT_ROOT)

# Locate traffic_gen from the scripts directory
sys.path.append(os.path.join(PROJECT_ROOT, "scripts"))
from traffic_gen import TRAFFIC_GENERATORS

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
  cfg["esp_proposal"] = f"{base['esp']}-{dh}" if cfg.get("pfs") else base["esp"]


def render_ipsec_conf(local_ip, local_id, remote_ip, remote_id, cfg):
  """Replaces Jinja2 with a native multi-line Python f-string.

  Guarantees exact strongSwan indentation and pure Unix LF line breaks.
  """
  lines = [
      "config setup",
      '    charondebug="ike 2, knl 2, cfg 2"',
      "    uniqueids=no",
      "",
      "conn test-conn",
      "    auto=add",
      f"    type={cfg['mode']}",
      f"    keyexchange={cfg['ikev']}",
      "    authby=secret",
      f"    left={local_ip}",
      f"    leftid=@{local_id}",
      f"    leftsubnet={local_ip}/32",
      f"    right={remote_ip}",
      f"    rightid=@{remote_id}",
      f"    rightsubnet={remote_ip}/32",
      f"    ike={cfg['ike_proposal']}!",
      f"    esp={cfg['esp_proposal']}!",
      f"    ikelifetime={cfg['keylife']}",
      f"    lifetime={cfg['keylife']}",
      "",
  ]
  return "\n".join(lines)


def push_to_container(host, content):
  """Injects configuration via Base64 stream to bypass file locks and mount errors."""
  b64_data = base64.b64encode(content.encode("utf-8")).decode("ascii")
  subprocess.run(
      [
          "docker",
          "exec",
          host,
          "sh",
          "-c",
          f"echo {b64_data} | base64 -d > /etc/ipsec.conf",
      ],
      check=True,
  )


def push_config(cfg):
  os.makedirs("configs/generated", exist_ok=True)
  build_proposals(cfg)

  # Generate and push initiator configuration (vpn-left)
  conf_left = render_ipsec_conf(
      local_ip="192.168.50.10",
      local_id="left",
      remote_ip="192.168.50.11",
      remote_id="right",
      cfg=cfg,
  )
  with open("configs/generated/left.conf", "w", newline="\n") as f:
    f.write(conf_left)
  push_to_container("vpn-left", conf_left)

  # Generate and push responder configuration (vpn-right)
  conf_right = render_ipsec_conf(
      local_ip="192.168.50.11",
      local_id="right",
      remote_ip="192.168.50.10",
      remote_id="left",
      cfg=cfg,
  )
  with open("configs/generated/right.conf", "w", newline="\n") as f:
    f.write(conf_right)
  push_to_container("vpn-right", conf_right)


def reload_ipsec():
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
      err_lines = [
          line.strip() for line in up_output.splitlines() if line.strip()
      ]
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