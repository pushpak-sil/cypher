import itertools, json

MODES = ["tunnel", "transport"]
IKEV = ["ikev2", "ikev1"]
CIPHER_PROFILES = {
    "aes128_cbc":     {"esp": "aes128-sha256", "ike": "aes128-sha256-modp2048"},
    "aes256_cbc":     {"esp": "aes256-sha256", "ike": "aes256-sha256-modp2048"},
    "aes256_gcm":     {"esp": "aes256gcm16",   "ike": "aes256-sha256-modp2048"},
    "aes256_cbc_hmac":{"esp": "aes256-sha1",   "ike": "aes256-sha1-modp2048"},
}
DH_GROUPS = ["modp1024", "modp2048", "ecp256"]
PFS_OPTIONS = [True, False]
KEYLIFE = ["5m", "60m"]

TRAFFIC_TYPES = ["icmp", "web", "voip", "video", "email"]
REPEATS_PER_COMBO = 5   # <-- this is what multiplies your dataset size

def build_matrix():
    curated_crypto = [
        {"mode": "tunnel", "ikev": "ikev2", "cipher_profile": "aes256_gcm", "dh_group": "modp2048", "pfs": True, "keylife": "20m"},
        {"mode": "tunnel", "ikev": "ikev2", "cipher_profile": "aes128_cbc", "dh_group": "modp1024", "pfs": False, "keylife": "60m"},
        {"mode": "transport", "ikev": "ikev2", "cipher_profile": "aes256_cbc_hmac", "dh_group": "modp2048", "pfs": True, "keylife": "20m"},
        {"mode": "tunnel", "ikev": "ikev1", "cipher_profile": "aes256_cbc", "dh_group": "modp1024", "pfs": False, "keylife": "60m"},
    ]
    configs = []
    run_id = 0
    for crypto in curated_crypto:
        for ttype in TRAFFIC_TYPES:
            for rep in range(REPEATS_PER_COMBO):
                cfg = dict(crypto)
                cfg["traffic_type"] = ttype
                cfg["run_id"] = f"run_{run_id:03d}"
                configs.append(cfg)
                run_id += 1
    return configs

if __name__ == "__main__":
    matrix = build_matrix()
    print(f"Generated {len(matrix)} total runs "
          f"({len(matrix)//REPEATS_PER_COMBO} unique combos × {REPEATS_PER_COMBO} repeats)")
    with open("configs/matrix.json", "w") as f:
        json.dump(matrix, f, indent=2)