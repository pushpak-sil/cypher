"""
Given a list of ESP packets, compute a fixed set of numeric statistics
describing that traffic flow -- this is the feature vector the ML
classifier will learn from.
"""

import numpy as np

MIN_PACKETS_REQUIRED = 5   # below this, statistics are unreliable/meaningless

def extract_features(esp_packets, local_ip="192.168.50.10"):
    if len(esp_packets) < MIN_PACKETS_REQUIRED:
        return None

    sizes = np.array([len(pkt) for pkt in esp_packets])
    times = np.array([float(pkt.time) for pkt in esp_packets])
    times = times - times[0]   # normalize so the flow starts at time 0

    if len(times) > 1:
        iats = np.diff(times)  # inter-arrival times: gap between consecutive packets
    else:
        iats = np.array([0.0])

    duration = max(times[-1], 0.001)   # avoid dividing by zero for instant flows

    outbound_count = sum(1 for pkt in esp_packets if pkt["IP"].src == local_ip)
    direction_ratio = outbound_count / len(esp_packets)

    return {
        "pkt_count":       len(esp_packets),
        "size_mean":       round(float(sizes.mean()), 2),
        "size_std":        round(float(sizes.std()), 2),
        "size_min":        int(sizes.min()),
        "size_max":        int(sizes.max()),
        "size_p25":        round(float(np.percentile(sizes, 25)), 2),
        "size_p75":        round(float(np.percentile(sizes, 75)), 2),
        "iat_mean":        round(float(iats.mean()), 4),
        "iat_std":         round(float(iats.std()), 4),
        "duration":        round(float(duration), 2),
        "bytes_per_sec":   round(float(sizes.sum() / duration), 2),
        "burstiness":      round(float(iats.std() / (iats.mean() + 1e-6)), 3),
        "direction_ratio": round(float(direction_ratio), 3),
    }