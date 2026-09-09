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


def extract_windowed_features(esp_packets, window_sec=3.0, step_sec=1.5, min_packets=5, local_ip="192.168.50.10"):
    """
    Slices esp_packets into overlapping time windows of `window_sec` seconds
    advancing by `step_sec` seconds.
    If the entire capture has >= min_packets but total duration < window_sec (e.g. short ping/burst),
    returns the whole flow as a single slice.
    """
    if not esp_packets or len(esp_packets) < min_packets:
        return []

    # Sort packets chronologically
    sorted_pkts = sorted(esp_packets, key=lambda p: float(p.time))
    t0 = float(sorted_pkts[0].time)
    t_end = float(sorted_pkts[-1].time)
    total_duration = t_end - t0

    # Short flow fallback: return full flow as one window
    if total_duration < window_sec:
        feat = extract_features(sorted_pkts, local_ip=local_ip)
        if feat:
            feat["window_idx"] = 0
            feat["window_start"] = 0.0
            feat["window_end"] = round(total_duration, 2)
            return [feat]
        return []

    # Sliding window extraction
    windows = []
    w_start = 0.0
    w_idx = 0

    while w_start < total_duration:
        w_end = w_start + window_sec
        # Select packets falling inside [t0 + w_start, t0 + w_end]
        window_pkts = [
            p for p in sorted_pkts
            if (t0 + w_start) <= float(p.time) <= (t0 + w_end)
        ]

        if len(window_pkts) >= min_packets:
            feat = extract_features(window_pkts, local_ip=local_ip)
            if feat:
                feat["window_idx"] = w_idx
                feat["window_start"] = round(w_start, 2)
                feat["window_end"] = round(w_end, 2)
                windows.append(feat)
                w_idx += 1

        w_start += step_sec

    # If windows empty despite enough packets (e.g., uneven spacing), fallback to whole flow
    if not windows:
        feat = extract_features(sorted_pkts, local_ip=local_ip)
        if feat:
            feat["window_idx"] = 0
            feat["window_start"] = 0.0
            feat["window_end"] = round(total_duration, 2)
            windows.append(feat)

    return windows