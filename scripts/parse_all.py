"""
Reads manifest.json, processes every completed run's pcap file into a
feature row, and writes the combined result to training_data.csv --
the final file handed off for ML training.
"""

import json
import csv
import os

from parse_pcap import load_packets, get_esp_packets
from feature_extraction import extract_features

MANIFEST_PATH = "manifest.json"
OUTPUT_CSV = "training_data.csv"


def process_run(entry):
    """Returns (row_dict, None) on success, or (None, reason_string) if this run should be skipped."""
    if not entry.get("tunnel_established", False):
        return None, "tunnel not established"

    pcap_path = entry["pcap_file"]
    if not os.path.exists(pcap_path):
        return None, "pcap file missing on disk"

    packets = load_packets(pcap_path)
    esp_packets = get_esp_packets(packets)
    features = extract_features(esp_packets)

    if features is None:
        return None, f"too few ESP packets ({len(esp_packets)})"

    row = {
        "run_id":      entry["run_id"],
        "mode":        entry["mode"],
        "ike_version": entry["ikev"],
        "cipher":      entry["cipher_profile"],
        "dh_group":    entry["dh_group"],
        "pfs":         entry["pfs"],
        **features,
        "traffic_type": entry["traffic_type"],
    }
    return row, None


def main():
    with open(MANIFEST_PATH) as f:
        manifest = json.load(f)

    rows = []
    skipped = []

    for entry in manifest:
        row, reason = process_run(entry)
        if row is not None:
            rows.append(row)
        else:
            skipped.append((entry["run_id"], reason))

    if not rows:
        print("ERROR: no valid rows produced. Check manifest.json and the captures/ folder.")
        return

    fieldnames = list(rows[0].keys())
    # newline="" is REQUIRED on Windows for the csv module -- without it, Excel/pandas
    # will show a blank row after every real row, because Windows' default text mode
    # adds its own line ending on top of the one csv.writer already adds.
    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {OUTPUT_CSV}")
    if skipped:
        print(f"Skipped {len(skipped)} runs:")
        for run_id, reason in skipped:
            print(f"  {run_id}: {reason}")


if __name__ == "__main__":
    main()