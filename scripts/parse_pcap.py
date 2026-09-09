"""
Low-level pcap reading utilities: given a .pcap file, sort its packets
into IKE / ESP / AH categories. No statistics are computed here.
"""

from scapy.all import rdpcap, IP, IPv6, UDP, Raw

NATT_PORT = 4500
MIN_ESP_PAYLOAD_BYTES = 8   # SPI (4 bytes) + sequence number (4 bytes)

ESP_PROTO = 50   # IP protocol / IPv6 next-header value for ESP
AH_PROTO = 51    # IP protocol / IPv6 next-header value for AH


def _l3_proto(pkt):
    """
    Return the L3 payload protocol number for an IPv4 or IPv6 packet,
    or None if the packet carries neither. IPv4 stores it in `proto`,
    IPv6 in `nh` (next header). Handling both is what lets the analyzer
    support IPv6 IPsec tunnels, not just IPv4.
    """
    if pkt.haslayer(IP):
        return pkt[IP].proto
    if pkt.haslayer(IPv6):
        return pkt[IPv6].nh
    return None

def load_packets(pcap_path):
    """Read every packet in the file into a Python list of Scapy packet objects."""
    return rdpcap(pcap_path)

def is_natt_keepalive(pkt):
    """
    strongSwan periodically sends tiny 1-byte 'keepalive' packets over
    UDP/4500 to stop NAT devices from forgetting the connection mapping.
    These are NOT real encrypted data and must be excluded, or they'll
    pollute our packet-size statistics with fake tiny values.
    """
    if pkt.haslayer(Raw):
        return len(pkt[Raw].load) <= 1
    return True

def get_esp_packets(packets):
    """
    Return genuine ESP data packets only -- whether raw ESP (IP protocol 50
    or IPv6 next-header 50) or NAT-T-wrapped ESP (UDP port 4500), and
    excluding keepalives. Works for both IPv4 and IPv6 captures.
    """
    esp_packets = []
    for pkt in packets:
        if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            continue

        if _l3_proto(pkt) == ESP_PROTO:
            esp_packets.append(pkt)
            continue

        if pkt.haslayer(UDP) and (pkt[UDP].sport == NATT_PORT or pkt[UDP].dport == NATT_PORT):
            if is_natt_keepalive(pkt):
                continue
            if pkt.haslayer(Raw) and len(pkt[Raw].load) >= MIN_ESP_PAYLOAD_BYTES:
                esp_packets.append(pkt)

    return esp_packets

def get_ike_packets(packets):
    """IKE negotiation runs over UDP port 500 (and later 4500 once NAT-T is active)."""
    return [p for p in packets
            if p.haslayer(UDP) and (p[UDP].sport == 500 or p[UDP].dport == 500)]

def get_ah_packets(packets):
    """AH uses IP protocol number 51 (IPv4) or next-header 51 (IPv6)."""
    return [p for p in packets
            if (p.haslayer(IP) or p.haslayer(IPv6)) and _l3_proto(p) == AH_PROTO]