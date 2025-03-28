import random
from scapy.all import Ether, IP, TCP, UDP, Raw
import os

def generate_random_mac():
    # Generate the first octet, clear the I/G bit and set the U/L bit.
    # (first_octet & 0xFC) clears the two least-significant bits.
    # OR-ing with 0x02 sets the U/L bit (bit 1) and ensures the I/G bit (bit 0) is 0.
    first_octet = (random.randint(0, 255) & 0xFC) | 0x02
    # Generate the remaining five octets randomly.
    remaining = [random.randint(0, 255) for _ in range(5)]
    return ":".join("{:02x}".format(octet) for octet in [first_octet] + remaining)

def generate_random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def generate_random_port():
    return random.randint(1024, 65535)

def generate_random_sni(length):
    # Simple random SNI generator (you can customize this as needed)
    # This version preserves the original length.
    letters = "abcdefghijklmnopqrstuvwxyz"
    return "".join(random.choices(letters, k=(length-4))) + ".com" # -4 to account for the ".com" suffix

def occlude_D1(packets):
    """
    D1: Anonymize strong identification information (MAC/IP addresses and ports) 
    while preserving the direction of traffic. Random values are generated once 
    per file and then reused for packets in the same pcap.
    """
    mac_map = {}
    ip_map = {}
    port_map = {}
    
    for pkt in packets:
        try:
            if pkt.haslayer(Ether):
                src_mac = pkt[Ether].src
                dst_mac = pkt[Ether].dst
                if src_mac not in mac_map:
                    mac_map[src_mac] = generate_random_mac()
                if dst_mac not in mac_map:
                    mac_map[dst_mac] = generate_random_mac()
                pkt[Ether].src = mac_map[src_mac]
                pkt[Ether].dst = mac_map[dst_mac]
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                if src_ip not in ip_map:
                    ip_map[src_ip] = generate_random_ip()
                if dst_ip not in ip_map:
                    ip_map[dst_ip] = generate_random_ip()
                pkt[IP].src = ip_map[src_ip]
                pkt[IP].dst = ip_map[dst_ip]
            if pkt.haslayer(TCP):
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                if sport not in port_map:
                    port_map[sport] = generate_random_port()
                if dport not in port_map:
                    port_map[dport] = generate_random_port()
                pkt[TCP].sport = port_map[sport]
                pkt[TCP].dport = port_map[dport]
            elif pkt.haslayer(UDP):
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                if sport not in port_map:
                    port_map[sport] = generate_random_port()
                if dport not in port_map:
                    port_map[dport] = generate_random_port()
                pkt[UDP].sport = port_map[sport]
                pkt[UDP].dport = port_map[dport]
        except Exception:
            raise
    return packets

def occlude_D2(packets, sni):
    """
    D2: Anonymize the SNI fields.
    For each packet, if the given SNI is found in the Raw payload,
    replace it with a random SNI of the same length to preserve payload size.
    """
    random_sni = generate_random_sni(len(sni))
    encoded_sni = sni.encode()
    replacement = random_sni.encode()

    for pkt in packets:
        try:
            if pkt.haslayer("Raw"):
                payload = pkt["Raw"].load
                if encoded_sni in payload:
                    new_payload = payload.replace(encoded_sni, replacement)
                    pkt["Raw"].load = new_payload
                    # Force recalculation of IP/TCP length and checksum.
                    if pkt.haslayer("IP"):
                        pkt["IP"].len = None
                        pkt["IP"].chksum = None
                    if pkt.haslayer("TCP"):
                        pkt["TCP"].chksum = None
        except Exception:
            raise
    return packets

def occlude_C(packets):
    """
    C: Randomize the IP ID, IP header checksum, and TCP sequence/acknowledgment numbers 
    while preserving the relative differences between packets.
    
    For a single-session pcap (one conversation), adjust the two flows separately:
      - For flow A→B (key = (src, sport, dst, dport))
      - For flow B→A (key = (dst, dport, src, sport))
      
    Then, for each packet, adjust its sequence number using its flow's baseline and 
    its ACK number using the reverse flow's baseline.
    """
    import random

    # Global IP adjustment: use the first IP packet as the baseline.
    ip_id_offset = None
    first_ip_id = None

    # Build a dictionary for TCP flow baselines.
    # Key: (src, sport, dst, dport) for each flow direction.
    flows = {}  # Each value is a dict with keys 'first_seq' and 'offset'

    # First pass: determine baselines for each TCP flow and the IP ID baseline.
    for pkt in packets:
        try:
            if pkt.haslayer("IP"):
                if ip_id_offset is None:
                    ip_id_offset = random.randint(0, 65535)
                    first_ip_id = pkt["IP"].id
            if pkt.haslayer("TCP"):
                key = (pkt["IP"].src, pkt["TCP"].sport, pkt["IP"].dst, pkt["TCP"].dport)
                if key not in flows:
                    flows[key] = {
                        'first_seq': pkt["TCP"].seq,
                        'offset': random.randint(0, 2**32 - 1)
                    }
        except Exception:
            raise

    # Second pass: update each packet based on the corresponding flow baselines.
    for pkt in packets:
        try:
            # Adjust IP ID field
            if pkt.haslayer("IP"):
                pkt["IP"].id = (ip_id_offset + (pkt["IP"].id - first_ip_id)) % 65536
                pkt["IP"].chksum = None  # Force recalculation later.
            if pkt.haslayer("TCP"):
                # Update sequence number for the packet's flow.
                key = (pkt["IP"].src, pkt["TCP"].sport, pkt["IP"].dst, pkt["TCP"].dport)
                if key in flows:
                    first_seq = flows[key]['first_seq']
                    offset = flows[key]['offset']
                    pkt["TCP"].seq = (offset + (pkt["TCP"].seq - first_seq)) % (2**32)
                # For ACK numbers, use the reverse flow's baseline.
                rev_key = (pkt["IP"].dst, pkt["TCP"].dport, pkt["IP"].src, pkt["TCP"].sport)
                if hasattr(pkt["TCP"], "ack") and pkt["TCP"].ack is not None and rev_key in flows:
                    rev_first_seq = flows[rev_key]['first_seq']
                    rev_offset = flows[rev_key]['offset']
                    pkt["TCP"].ack = (rev_offset + (pkt["TCP"].ack - rev_first_seq)) % (2**32)
                pkt["TCP"].chksum = None  # Force recalculation.
        except Exception:
            raise

    return packets

def occlude_T(packets):
    """
    T: Randomize the TCP window size and TCP options values while preserving their relative differences.
    For TCP Timestamp options, a per-flow random base is initialized using the first occurrence in that flow,
    and the time gaps (delta) from the original values are preserved for subsequent packets.
    """
    # Dictionaries to store per-flow baselines.
    window_offsets = {}  # key: (src, sport, dst, dport) -> (offset, first_window)
    ts_offsets = {}      # key: (src, sport, dst, dport) -> random timestamp offset
    ts_baselines = {}    # key: (src, sport, dst, dport) -> (first_ts_val, first_tsecr)

    for pkt in packets:
        try:
            if pkt.haslayer("IP") and pkt.haslayer("TCP"):
                # Define a flow key for this packet's direction.
                flow_key = (pkt["IP"].src, pkt["TCP"].sport, pkt["IP"].dst, pkt["TCP"].dport)

                # Adjust TCP window size per flow.
                if flow_key not in window_offsets:
                    window_offsets[flow_key] = (random.randint(0, 65535), pkt["TCP"].window)
                offset, first_win = window_offsets[flow_key]
                pkt["TCP"].window = (offset + (pkt["TCP"].window - first_win)) % 65536

                # Process TCP options if present.
                if pkt["TCP"].options:
                    new_options = []
                    for opt in pkt["TCP"].options:
                        kind = opt[0]
                        value = opt[1]
                        if kind == "Timestamp" and isinstance(value, tuple):
                            # value is expected to be a tuple: (tsval, tsecr)
                            orig_ts_val, orig_tsecr = value
                            if flow_key not in ts_offsets:
                                # First occurrence in this flow: initialize baseline and offset.
                                ts_offsets[flow_key] = random.randint(0, 4294967295)
                                ts_baselines[flow_key] = (orig_ts_val, orig_tsecr)
                                new_ts_val = ts_offsets[flow_key]
                                new_tsecr = ts_offsets[flow_key]
                            else:
                                base = ts_offsets[flow_key]
                                first_ts_val, first_tsecr = ts_baselines[flow_key]
                                new_ts_val = (base + (orig_ts_val - first_ts_val)) % (2**32)
                                new_tsecr = (base + (orig_tsecr - first_tsecr)) % (2**32)
                            new_options.append((kind, (new_ts_val, new_tsecr)))
                        else:
                            # For other options, apply similar randomization as before.
                            if value is None:
                                new_val = None
                            elif isinstance(value, bytes):
                                new_val = bytes(random.randint(0, 255) for _ in range(len(value)))
                            elif isinstance(value, int):
                                if kind == 'WScale':
                                    new_val = random.randint(1, 14)
                                elif kind == 'MSS':
                                    new_val = random.randint(1, 1460)
                                else:
                                    new_val = random.randint(0, 255)
                            elif isinstance(value, tuple):
                                new_val = tuple(random.randint(0, 255) if isinstance(elem, int) else elem for elem in value)
                            else:
                                new_val = value
                            new_options.append((kind, new_val))
                    pkt["TCP"].options = new_options

                # Force recalculation of the TCP checksum.
                pkt["TCP"].chksum = None
        except Exception:
            raise
    return packets

def occlude_CTD(packets, sni):
    """
    CTD: Apply D1, D2, T, and C occlusions sequentially.
    """
    packets = occlude_D1(packets)
    packets = occlude_D2(packets, sni)
    packets = occlude_T(packets)
    packets = occlude_C(packets)
    return packets

def occlude_H1(packets):
    """
    H1: Retain only Ethernet, IP, TCP/UDP header fields to identify the contribution of header information.
    """
    for pkt in packets:
        try:
            # Check if the packet has a Raw layer (payload)
            if pkt.haslayer(Raw):
                # Remove the Raw payload
                del pkt[Raw]

        except Exception:
            raise

    return packets

def occlude_P1(packets):
    """
    P1: Retain only the payload (Raw layer) and set all header-related fields to 0.
    If no Raw payload is present, create a packet with headers set to 0.
    """
    new_packets = []

    for pkt in packets:
        try:
            # Check if the packet has a Raw layer (payload)
            if pkt.haslayer(Raw):
                raw_payload = pkt[Raw].load
            else:
                raw_payload = b''

            # Detect if it's TCP or UDP and create a zeroed-out header accordingly
            if pkt.haslayer(TCP):
                new_transport_layer = TCP(
                    sport=0,
                    dport=0,
                    seq=0,
                    ack=0,
                    dataofs=0,
                    reserved=0,
                    flags=0,
                    window=0,
                    chksum=0,
                    urgptr=0,
                )
            elif pkt.haslayer(UDP):
                new_transport_layer = UDP(
                    sport=0,
                    dport=0,
                    len=0,
                    chksum=0,
                )
            else:
                # No TCP or UDP, just create an empty IP header with Raw payload
                new_transport_layer = b''

            # Create a new packet with zeroed headers and the original payload
            new_pkt = (
                Ether(dst="00:00:00:00:00:00", src="00:00:00:00:00:00", type=0)
                / IP(
                    version=0,
                    ihl=0,
                    tos=0,
                    len=0,
                    id=0,
                    flags=0,
                    frag=0,
                    ttl=0,
                    proto=0,
                    chksum=0,
                    src="0.0.0.0",
                    dst="0.0.0.0",
                )
                / new_transport_layer
                / Raw(raw_payload)
            )

            new_packets.append(new_pkt)

        except Exception:
            raise

    return new_packets

def occlude_E1(packets, packets_pyshark):
    """
    E1: Mask any plaintext information—including header values and unencrypted payloads—with 0x00.
    Only leave the encrypted payload unchanged.
    
    This version zips the Scapy packets with the corresponding PyShark packets,
    and if the PyShark packet does not indicate TLS or QUIC (i.e. not encrypted),
    it replaces the Raw payload with 0x00 bytes. Finally, it calls occlude_P1
    to mask header fields.
    """
    for pkt_sc, pkt_py in zip(packets, packets_pyshark):
        try:
            has_tls = hasattr(pkt_py, 'tls') or ('tls' in pkt_py.field_names if hasattr(pkt_py, 'field_names') else False)
            has_quic = hasattr(pkt_py, 'quic') or ('quic' in pkt_py.field_names if hasattr(pkt_py, 'field_names') else False)
            
            if not (has_tls or has_quic):
                if pkt_sc.haslayer(Raw):
                    pkt_sc[Raw].load = b'\x00' * len(pkt_sc[Raw].load)
        except Exception:
            raise

    # After processing payloads, mask header values using occlude_P1.
    packets = occlude_P1(packets)
    return packets


def occlude_E2(packets, packets_pyshark):
    """
    E2: Mask the encrypted payload with 0xFF.
    """
    for pkt_sc, pkt_py in zip(packets, packets_pyshark):
        try:
            has_tls = hasattr(pkt_py, 'tls') or ('tls' in pkt_py.field_names if hasattr(pkt_py, 'field_names') else False)
            has_quic = hasattr(pkt_py, 'quic') or ('quic' in pkt_py.field_names if hasattr(pkt_py, 'field_names') else False)
            
            if not (has_tls or has_quic):
                if pkt_sc.haslayer(Raw):
                    pkt_sc[Raw].load = b'\x00' * len(pkt_sc[Raw].load)
            else:
                if pkt_sc.haslayer(Raw):
                    pkt_sc[Raw].load = b'\xff' * len(pkt_sc[Raw].load)
        except Exception:
            raise

    # After processing payloads, mask header values using occlude_P1.
    packets = occlude_P1(packets)
    return packets

def occlude_E3(packets, packets_pyshark):
    """
    E3: Based on E1, replace the encrypted payload with random hexadecimal values.
    """
    for pkt_sc, pkt_py in zip(packets, packets_pyshark):
        try:
            has_tls = hasattr(pkt_py, 'tls') or ('tls' in pkt_py.field_names if hasattr(pkt_py, 'field_names') else False)
            has_quic = hasattr(pkt_py, 'quic') or ('quic' in pkt_py.field_names if hasattr(pkt_py, 'field_names') else False)
            
            if not (has_tls or has_quic):
                if pkt_sc.haslayer(Raw):
                    pkt_sc[Raw].load = b'\x00' * len(pkt_sc[Raw].load)
            else:
                if pkt_sc.haslayer(Raw):
                    pkt_sc[Raw].load = os.urandom(len(pkt_sc[Raw].load))
        except Exception:
            raise

    # After processing payloads, mask header values using occlude_P1.
    packets = occlude_P1(packets)
    return packets