"""
core/dissector.py
Deep Packet Dissector for IPsec VPN captures (IKEv1, IKEv2, ESP, AH, NAT-T).
Extracts protocol characteristics, cryptographic proposals, transforms,
SPIs, sequence numbers, and infer operational modes.
"""

import struct
from scapy.all import rdpcap, PcapReader, IP, IPv6, UDP, Raw

# Transform Mappings according to IANA IKEv2 Parameters / RFC 7296
ENCR_MAP = {
    1: "DES-IV64",
    2: "DES",
    3: "3DES",
    4: "RC5",
    5: "IDEA",
    6: "CAST",
    7: "Blowfish",
    8: "3IDEA",
    9: "DES-IV32",
    11: "Null",
    12: "AES-CBC",
    13: "AES-CTR",
    18: "AES-CCM-8",
    19: "AES-CCM-12",
    20: "AES-GCM-16",
    21: "AES-GCM-12",
    22: "AES-GCM-8",
    28: "ChaCha20-Poly1305",
}

PRF_MAP = {
    1: "PRF_HMAC_MD5",
    2: "PRF_HMAC_SHA1",
    3: "PRF_HMAC_TIGER",
    4: "PRF_AES128_XCBC",
    5: "PRF_HMAC_SHA2_256",
    6: "PRF_HMAC_SHA2_384",
    7: "PRF_HMAC_SHA2_512",
    8: "PRF_AES128_CMAC",
}

INTEG_MAP = {
    0: "NONE",
    1: "AUTH_HMAC_MD5_96",
    2: "AUTH_HMAC_SHA1_96",
    3: "AUTH_DES_MAC",
    4: "AUTH_KPDK_MD5",
    5: "AUTH_AES_XCBC_96",
    8: "AUTH_HMAC_SHA2_256_96",
    12: "AUTH_HMAC_SHA2_256_128",
    13: "AUTH_HMAC_SHA2_384_192",
    14: "AUTH_HMAC_SHA2_512_256",
}

DH_MAP = {
    0: "NONE",
    1: "modp768 (Group 1 - Deprecated)",
    2: "modp1024 (Group 2 - Weak)",
    5: "modp1536 (Group 5 - Weak)",
    14: "modp2048 (Group 14 - Standard)",
    15: "modp3072 (Group 15 - High)",
    16: "modp4096 (Group 16 - High)",
    19: "ecp256 (Group 19 - NIST P-256)",
    20: "ecp384 (Group 20 - NIST P-384)",
    21: "ecp521 (Group 21 - NIST P-521)",
    31: "curve25519 (Group 31 - Ed25519)",
}

IKEV2_EXCHANGE_MAP = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
}

IKEV1_EXCHANGE_MAP = {
    2: "Identity Protection (Main Mode)",
    4: "Aggressive Mode",
    5: "Informational",
    32: "Quick Mode",
}


def parse_ike_payloads(data, next_payload, version=2):
    """
    Parses generic IKE/ISAKMP payload chains starting at next_payload.
    Decodes SA proposals, transforms, and attributes.
    """
    payloads = []
    offset = 0
    curr_np = next_payload

    while curr_np != 0 and offset + 4 <= len(data):
        np = data[offset]
        crit_flag = (data[offset + 1] & 0x80) != 0
        p_len = struct.unpack("!H", data[offset + 2:offset + 4])[0]
        if p_len < 4 or offset + p_len > len(data):
            break

        body = data[offset + 4:offset + p_len]
        p_info = {
            "type": curr_np,
            "length": p_len,
            "critical": crit_flag,
        }

        # Payload Type 33 (IKEv2 SA) or 1 (IKEv1 SA)
        if (version == 2 and curr_np == 33) or (version == 1 and curr_np == 1):
            p_info["name"] = "Security Association (SA)"
            p_info["proposals"] = parse_sa_proposals(body, version=version)
        elif (version == 2 and curr_np == 34) or (version == 1 and curr_np == 4):
            p_info["name"] = "Key Exchange (KE)"
            if len(body) >= 4 and version == 2:
                dh_group = struct.unpack("!H", body[0:2])[0]
                p_info["dh_group"] = DH_MAP.get(dh_group, f"Group {dh_group}")
                p_info["dh_group_id"] = dh_group
        elif (version == 2 and curr_np == 40) or (version == 1 and curr_np == 10):
            p_info["name"] = "Nonce (Ni/Nr)"
            p_info["nonce_len"] = len(body)
        elif curr_np == 44:
            p_info["name"] = "Traffic Selector Initiator (TSi)"
        elif curr_np == 45:
            p_info["name"] = "Traffic Selector Responder (TSr)"
        elif curr_np == 46:
            p_info["name"] = "Encrypted and Authenticated (SK)"
        elif curr_np == 36:
            p_info["name"] = "Certificate Request (CERTREQ)"
        elif curr_np == 37:
            p_info["name"] = "Certificate (CERT)"
        elif curr_np == 38:
            p_info["name"] = "Authentication (AUTH)"
        elif curr_np == 41:
            p_info["name"] = "Notify (N)"
        else:
            p_info["name"] = f"Payload-{curr_np}"

        payloads.append(p_info)
        curr_np = np
        offset += p_len

    return payloads


def parse_sa_proposals(body, version=2):
    """
    Extracts proposals and cryptographic transform choices from SA payload.
    Handles both IKEv2 and IKEv1 (skips 8-byte DOI/Situation in IKEv1).
    """
    proposals = []
    p_offset = 0

    # In IKEv1, SA payload body starts with DOI (4 bytes) + Situation (4 bytes)
    if version == 1:
        if len(body) < 8:
            return proposals
        doi = struct.unpack("!I", body[:4])[0]
        # Skip DOI (4 bytes) + Situation (4 bytes)
        p_offset = 8

    while p_offset + 8 <= len(body):
        more_props = body[p_offset] != 0
        prop_len = struct.unpack("!H", body[p_offset + 2:p_offset + 4])[0]
        if prop_len < 8 or p_offset + prop_len > len(body):
            break

        prop_num = body[p_offset + 4]
        proto_id = body[p_offset + 5]
        spi_sz = body[p_offset + 6]
        num_transforms = body[p_offset + 7]

        proto_name = {1: "IKE/ISAKMP", 2: "AH", 3: "ESP"}.get(proto_id, f"Proto-{proto_id}")
        spi = body[p_offset + 8:p_offset + 8 + spi_sz].hex() if spi_sz > 0 else ""

        prop_data = {
            "proposal_num": prop_num,
            "protocol": proto_name,
            "spi": spi,
            "num_transforms": num_transforms,
            "transforms": [],
        }

        # Parse Transforms
        t_offset = p_offset + 8 + spi_sz
        for _ in range(num_transforms):
            if t_offset + 8 > p_offset + prop_len:
                break
            t_more = body[t_offset] != 0
            t_len = struct.unpack("!H", body[t_offset + 2:t_offset + 4])[0]
            if t_len < 8 or t_offset + t_len > len(body):
                break

            if version == 1:
                # IKEv1 Transform Header: [t_num (1B), t_id (1B), reserved (2B)]
                t_num = body[t_offset + 4]
                t_id = body[t_offset + 5]
                attr_offset = t_offset + 8

                # Read IKEv1 attributes
                encr_algo = None
                hash_algo = None
                auth_method = None
                dh_grp = None
                key_len = None
                life_sec = None

                while attr_offset + 4 <= t_offset + t_len:
                    attr_type_raw = struct.unpack("!H", body[attr_offset:attr_offset + 2])[0]
                    is_af = (attr_type_raw & 0x8000) != 0
                    attr_type = attr_type_raw & 0x7FFF
                    if is_af:
                        attr_val = struct.unpack("!H", body[attr_offset + 2:attr_offset + 4])[0]
                        attr_offset += 4
                    else:
                        attr_val_len = struct.unpack("!H", body[attr_offset + 2:attr_offset + 4])[0]
                        attr_val = int.from_bytes(body[attr_offset + 4:attr_offset + 4 + attr_val_len], "big")
                        attr_offset += 4 + attr_val_len

                    if attr_type == 1:  # Encryption Algo (1=DES, 5=3DES, 7=AES-CBC)
                        encr_map_v1 = {1: "DES", 2: "IDEA", 3: "Blowfish", 5: "3DES", 7: "AES-CBC"}
                        encr_algo = encr_map_v1.get(attr_val, f"ENCR-{attr_val}")
                    elif attr_type == 2:  # Hash Algo (1=MD5, 2=SHA1, 4=SHA2-256, 5=SHA2-384, 6=SHA2-512)
                        hash_map_v1 = {1: "MD5", 2: "SHA1", 3: "TIGER", 4: "SHA2-256", 5: "SHA2-384", 6: "SHA2-512"}
                        hash_algo = hash_map_v1.get(attr_val, f"HASH-{attr_val}")
                    elif attr_type == 3:  # Auth Method
                        auth_map_v1 = {1: "PSK", 2: "DSS", 3: "RSA-Sig", 4: "RSA-Enc"}
                        auth_method = auth_map_v1.get(attr_val, f"AUTH-{attr_val}")
                    elif attr_type == 4:  # Group Description / DH
                        dh_grp = DH_MAP.get(attr_val, f"DH-{attr_val}")
                        dh_id = attr_val
                    elif attr_type == 14:  # Key Length in bits
                        key_len = attr_val
                    elif attr_type == 12:  # Life Duration in seconds
                        life_sec = attr_val

                if encr_algo:
                    cname = f"{encr_algo}/{key_len}" if key_len else encr_algo
                    prop_data["transforms"].append({"type": "Encryption", "name": cname, "key_length": key_len})
                if hash_algo:
                    prop_data["transforms"].append({"type": "Integrity", "name": hash_algo})
                if dh_grp:
                    prop_data["transforms"].append({"type": "DH Group", "name": dh_grp, "dh_group_id": dh_id})
                if life_sec:
                    prop_data["lifetime_seconds"] = life_sec

                t_offset += t_len
                continue

            # IKEv2 Transform Parsing
            t_type = body[t_offset + 4]
            t_id = struct.unpack("!H", body[t_offset + 6:t_offset + 8])[0]

            transform_info = {"type_id": t_type, "transform_id": t_id}

            # Decode attributes. In IKEv2 the only defined transform attribute
            # is type 14 (Key Length); encapsulation mode is NOT carried here
            # (that is an IKEv1 phase-2 attribute, and phase-2 is encrypted).
            attr_offset = t_offset + 8
            key_len = None
            while attr_offset + 4 <= t_offset + t_len:
                attr_type_raw = struct.unpack("!H", body[attr_offset:attr_offset + 2])[0]
                is_af = (attr_type_raw & 0x8000) != 0
                attr_type = attr_type_raw & 0x7FFF
                if is_af:
                    attr_val = struct.unpack("!H", body[attr_offset + 2:attr_offset + 4])[0]
                    attr_offset += 4
                else:
                    attr_val_len = struct.unpack("!H", body[attr_offset + 2:attr_offset + 4])[0]
                    attr_val = int.from_bytes(body[attr_offset + 4:attr_offset + 4 + attr_val_len], "big")
                    attr_offset += 4 + attr_val_len

                if attr_type == 14:  # Key Length in bits
                    key_len = attr_val

            if key_len:
                transform_info["key_length"] = key_len

            if t_type == 1:  # Encryption
                name = ENCR_MAP.get(t_id, f"ENCR-{t_id}")
                if key_len:
                    name += f"/{key_len}"
                transform_info["type"] = "Encryption"
                transform_info["name"] = name
            elif t_type == 2:  # PRF
                transform_info["type"] = "PRF"
                transform_info["name"] = PRF_MAP.get(t_id, f"PRF-{t_id}")
            elif t_type == 3:  # Integrity
                transform_info["type"] = "Integrity"
                transform_info["name"] = INTEG_MAP.get(t_id, f"AUTH-{t_id}")
            elif t_type == 4:  # Diffie-Hellman Group
                transform_info["type"] = "DH Group"
                transform_info["name"] = DH_MAP.get(t_id, f"DH-{t_id}")
                transform_info["dh_group_id"] = t_id
            elif t_type == 5:  # ESN
                transform_info["type"] = "Extended Sequence Numbers"
                transform_info["name"] = "ESN" if t_id == 1 else "No ESN"
            else:
                transform_info["type"] = f"Type-{t_type}"
                transform_info["name"] = f"Transform-{t_id}"

            prop_data["transforms"].append(transform_info)
            t_offset += t_len

        proposals.append(prop_data)
        p_offset += prop_len

    return proposals



def dissect_ike_packet(pkt):
    """
    Parses raw UDP packet on port 500 or 4500 into structured IKE header & payloads.
    """
    if not pkt.haslayer(UDP):
        return None

    raw_payload = bytes(pkt[UDP].payload)
    if not raw_payload:
        return None

    # Handle NAT-T encapsulation (UDP/4500): check for 4-byte Non-ESP marker
    is_natt = (pkt[UDP].sport == 4500 or pkt[UDP].dport == 4500)
    if is_natt:
        if len(raw_payload) < 4:
            return None
        if raw_payload[:4] == b"\x00\x00\x00\x00":
            raw_payload = raw_payload[4:]  # strip non-ESP marker
        else:
            return None  # This is an ESP packet over UDP 4500

    if len(raw_payload) < 28:
        return None

    init_spi = raw_payload[:8].hex()
    resp_spi = raw_payload[8:16].hex()
    next_payload = raw_payload[16]
    version_byte = raw_payload[17]
    major_v = (version_byte >> 4) & 0x0F
    minor_v = version_byte & 0x0F
    exchange_type = raw_payload[18]
    flags = raw_payload[19]
    msg_id = struct.unpack("!I", raw_payload[20:24])[0]
    total_len = struct.unpack("!I", raw_payload[24:28])[0]

    is_initiator = bool(flags & 0x08)
    is_response = bool(flags & 0x20)

    if major_v == 2:
        exchange_name = IKEV2_EXCHANGE_MAP.get(exchange_type, f"IKEv2-Exchange-{exchange_type}")
        version_str = f"IKEv2 (v{major_v}.{minor_v})"
    else:
        exchange_name = IKEV1_EXCHANGE_MAP.get(exchange_type, f"IKEv1-Exchange-{exchange_type}")
        version_str = f"IKEv1 (ISAKMP v{major_v}.{minor_v})"

    payloads = parse_ike_payloads(raw_payload[28:total_len], next_payload, version=major_v)

    src_ip = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src if pkt.haslayer(IPv6) else "unknown"
    dst_ip = pkt[IP].dst if pkt.haslayer(IP) else pkt[IPv6].dst if pkt.haslayer(IPv6) else "unknown"

    return {
        "timestamp": float(pkt.time),
        "src": f"{src_ip}:{pkt[UDP].sport}",
        "dst": f"{dst_ip}:{pkt[UDP].dport}",
        "version": version_str,
        "major_version": major_v,
        "minor_version": minor_v,
        "initiator_spi": init_spi,
        "responder_spi": resp_spi,
        "exchange_type": exchange_name,
        "exchange_id": exchange_type,
        "message_id": msg_id,
        "is_initiator": is_initiator,
        "is_response": is_response,
        "flags_raw": flags,
        "payloads": payloads,
    }


def dissect_esp_packet(pkt):
    """
    Dissects raw ESP packet (Proto 50) or UDP/4500 NAT-T ESP packet.
    Extracts SPI and Sequence Number.
    """
    raw_data = None
    if pkt.haslayer(IP) and pkt[IP].proto == 50:
        raw_data = bytes(pkt[IP].payload)
    elif pkt.haslayer(IPv6) and pkt[IPv6].nh == 50:
        raw_data = bytes(pkt[IPv6].payload)
    elif pkt.haslayer(UDP) and (pkt[UDP].sport == 4500 or pkt[UDP].dport == 4500):
        udp_load = bytes(pkt[UDP].payload)
        # NAT-T ESP packets do NOT start with 4 zeroes
        if len(udp_load) >= 8 and udp_load[:4] != b"\x00\x00\x00\x00":
            raw_data = udp_load

    if not raw_data or len(raw_data) < 8:
        return None

    spi_int = struct.unpack("!I", raw_data[:4])[0]
    spi_hex = f"0x{spi_int:08x}"
    seq_num = struct.unpack("!I", raw_data[4:8])[0]

    src_ip = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src if pkt.haslayer(IPv6) else ""
    dst_ip = pkt[IP].dst if pkt.haslayer(IP) else pkt[IPv6].dst if pkt.haslayer(IPv6) else ""

    return {
        "timestamp": float(pkt.time),
        "src": src_ip,
        "dst": dst_ip,
        "spi": spi_hex,
        "spi_int": spi_int,
        "sequence_number": seq_num,
        "packet_len": len(pkt),
        "payload_len": len(raw_data) - 8,
    }


def dissect_ah_packet(pkt):
    """
    Dissects Authentication Header (AH, Proto 51).
    """
    raw_data = None
    if pkt.haslayer(IP) and pkt[IP].proto == 51:
        raw_data = bytes(pkt[IP].payload)
    elif pkt.haslayer(IPv6) and pkt[IPv6].nh == 51:
        raw_data = bytes(pkt[IPv6].payload)

    if not raw_data or len(raw_data) < 12:
        return None

    next_hdr = raw_data[0]
    payload_len_val = raw_data[1]
    spi_int = struct.unpack("!I", raw_data[4:8])[0]
    seq_num = struct.unpack("!I", raw_data[8:12])[0]

    return {
        "timestamp": float(pkt.time),
        "next_header": next_hdr,
        "spi": f"0x{spi_int:08x}",
        "sequence_number": seq_num,
        "packet_len": len(pkt),
    }


def analyze_pcap(pcap_path):
    """
    Main entry point: analyzes raw PCAP file, performing complete protocol
    dissection, cryptographic parameter identification, and flow metrics.
    """
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        return {"error": f"Failed to read PCAP: {str(e)}"}

    ike_messages = []
    esp_records = []
    ah_records = []

    # Parsed Cryptographic parameters.
    # NOTE on observability: a passive capture only exposes the IKE (phase-1)
    # SA proposal in cleartext. The ESP data cipher, the encapsulation mode
    # (tunnel/transport) and PFS are all negotiated inside the ENCRYPTED
    # phase-2 exchange (IKE_AUTH / Quick Mode) or only revealed on a CHILD_SA
    # rekey. We therefore report those honestly as "Not Observed" unless the
    # capture actually contains the evidence, rather than fabricating a value.
    inferred_crypto = {
        "ike_version": "Unknown",
        "cipher": "Unknown",              # IKE (phase-1) cipher -- the only one on the wire
        "cipher_scope": "IKE (Phase-1) SA",
        "auth_algo": "Unknown",           # IKE (phase-1) integrity
        "dh_group": "Unknown",
        "dh_group_id": None,
        "pfs_enabled": False,             # back-compat bool: True only when positively observed
        "pfs_status": "Not Observed",     # "Enabled" | "Disabled" | "Not Observed"
        "mode": "Not Observed",           # tunnel/transport -- negotiated in encrypted phase-2
        "esp_cipher": "Not Observed",     # ESP data cipher -- negotiated in encrypted CHILD_SA
        "key_lifetime": "Standard (8h)",
        "observability_notes": [],
    }

    spis_observed = set()
    initiator_spis = set()
    responder_spis = set()

    for pkt in packets:
        # Check IKE
        if pkt.haslayer(UDP) and (pkt[UDP].sport in (500, 4500) or pkt[UDP].dport in (500, 4500)):
            ike_info = dissect_ike_packet(pkt)
            if ike_info:
                ike_messages.append(ike_info)
                inferred_crypto["ike_version"] = f"IKEv{ike_info['major_version']}"
                if ike_info.get("initiator_spi"):
                    initiator_spis.add(ike_info["initiator_spi"])
                if ike_info.get("responder_spi"):
                    responder_spis.add(ike_info["responder_spi"])

                for p in ike_info.get("payloads", []):
                    # Check DH group from KE payload
                    if "dh_group" in p:
                        inferred_crypto["dh_group"] = p["dh_group"]
                        inferred_crypto["dh_group_id"] = p.get("dh_group_id")

                    # Check SA proposals (IKE / phase-1 cipher suite -- observable)
                    for prop in p.get("proposals", []):
                        for trans in prop.get("transforms", []):
                            t_type = trans.get("type")
                            t_name = trans.get("name", "")
                            if t_type == "Encryption" and inferred_crypto["cipher"] == "Unknown":
                                inferred_crypto["cipher"] = t_name
                            elif t_type == "Integrity" and inferred_crypto["auth_algo"] == "Unknown":
                                inferred_crypto["auth_algo"] = t_name
                            elif t_type == "DH Group" and inferred_crypto["dh_group"] == "Unknown":
                                inferred_crypto["dh_group"] = t_name
                                inferred_crypto["dh_group_id"] = trans.get("dh_group_id")

                # PFS is only observable from a CHILD_SA rekey (CREATE_CHILD_SA,
                # exchange 36): a Key Exchange payload inside it means a fresh DH
                # was performed (PFS in use); its absence means the rekey reused
                # existing key material (no PFS). Initial handshakes carry no such
                # evidence, so the status stays "Not Observed".
                if ike_info.get("exchange_id") == 36:
                    has_ke = any(
                        str(pp.get("name", "")).startswith("Key Exchange")
                        for pp in ike_info.get("payloads", [])
                    )
                    inferred_crypto["pfs_status"] = "Enabled" if has_ke else "Disabled"
                    inferred_crypto["pfs_enabled"] = has_ke

        # Check ESP
        esp_info = dissect_esp_packet(pkt)
        if esp_info:
            esp_records.append(esp_info)
            spis_observed.add(esp_info["spi"])

        # Check AH
        ah_info = dissect_ah_packet(pkt)
        if ah_info:
            ah_records.append(ah_info)

    # Encapsulation mode and the ESP data cipher are negotiated inside the
    # encrypted phase-2 exchange (IKEv2 IKE_AUTH / IKEv1 Quick Mode), so a
    # passive capture cannot reveal them -- we report that honestly instead of
    # defaulting to "tunnel". Record caveats for the report/dashboard.
    if inferred_crypto["mode"] == "Not Observed":
        inferred_crypto["observability_notes"].append(
            "Encapsulation mode (tunnel/transport) is negotiated in the encrypted "
            "phase-2 exchange and is not determinable from a passive capture."
        )
    if inferred_crypto["esp_cipher"] == "Not Observed":
        inferred_crypto["observability_notes"].append(
            "ESP data cipher is negotiated in the encrypted CHILD_SA; the cipher "
            "shown is the observable IKE (phase-1) SA cipher."
        )
    if inferred_crypto["pfs_status"] == "Not Observed":
        inferred_crypto["observability_notes"].append(
            "PFS status requires a captured CHILD_SA rekey; none was present, so "
            "it is reported as Not Observed rather than assumed disabled."
        )

    # Replay Protection Analysis on ESP
    seq_analysis = {
        "total_esp_packets": len(esp_records),
        "unique_spis": list(spis_observed),
        "replay_window_ok": True,
        "out_of_order_count": 0,
        "duplicate_sequences": 0,
        "max_seq_observed": 0,
    }

    if esp_records:
        seen_seqs = {}
        for r in esp_records:
            spi = r["spi"]
            seq = r["sequence_number"]
            if spi not in seen_seqs:
                seen_seqs[spi] = []
            seen_seqs[spi].append(seq)

        for spi, seqs in seen_seqs.items():
            max_s = 0
            dups = len(seqs) - len(set(seqs))
            seq_analysis["duplicate_sequences"] += dups
            for s in seqs:
                if s < max_s:
                    seq_analysis["out_of_order_count"] += 1
                else:
                    max_s = s
            seq_analysis["max_seq_observed"] = max(seq_analysis["max_seq_observed"], max_s)

        if seq_analysis["duplicate_sequences"] > 0:
            seq_analysis["replay_window_ok"] = False

    return {
        "summary": {
            "total_packets": len(packets),
            "ike_packets": len(ike_messages),
            "esp_packets": len(esp_records),
            "ah_packets": len(ah_records),
            "protocol_types": [p for p, c in [("IKE", len(ike_messages)), ("ESP", len(esp_records)), ("AH", len(ah_records))] if c > 0],
        },
        "crypto_parameters": inferred_crypto,
        "ike_handshake": ike_messages,
        "esp_analysis": seq_analysis,
        "esp_sample_packets": esp_records[:50],  # first 50 packets for waterfall/table
    }


if __name__ == "__main__":
    import sys, json
    if len(sys.argv) > 1:
        pcap = sys.argv[1]
        res = analyze_pcap(pcap)
        print(json.dumps(res, indent=2, default=str))
    else:
        print("Usage: python -m core.dissector <pcap_file>")
