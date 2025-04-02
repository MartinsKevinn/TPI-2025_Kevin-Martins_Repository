from scapy.all import Raw, TCP, IP

def extract_tls_info(pkt):
    if not (pkt.haslayer(Raw) and pkt.haslayer(TCP) and pkt.haslayer(IP)):
        return None

    raw_load = pkt[Raw].load

    if not raw_load.startswith(b'\x16\x03'):  # TLS Handshake record
        return None

    try:
        tls_version_major = raw_load[1]
        tls_version_minor = raw_load[2]
        tls_version_str = f"{tls_version_major}.{tls_version_minor}"

        dest_ip = pkt[IP].dst
        sni_hostname = None

        # Extraire SNI si possible
        offset = 5 + 4
        session_id_len = raw_load[offset]
        offset += 1 + session_id_len

        cipher_suites_len = int.from_bytes(raw_load[offset:offset+2], 'big')
        offset += 2 + cipher_suites_len

        compression_methods_len = raw_load[offset]
        offset += 1 + compression_methods_len

        extensions_length = int.from_bytes(raw_load[offset:offset+2], 'big')
        offset += 2
        end = offset + extensions_length

        while offset + 4 <= end:
            ext_type = int.from_bytes(raw_load[offset:offset+2], 'big')
            ext_len = int.from_bytes(raw_load[offset+2:offset+4], 'big')
            offset += 4

            if ext_type == 0x00:  # SNI
                server_name_len = int.from_bytes(raw_load[offset+5:offset+7], 'big')
                sni_hostname = raw_load[offset+7:offset+7+server_name_len].decode(errors="ignore")
                break
            offset += ext_len

    except Exception:
        return None

    return {
        "dest_ip": dest_ip,
        "sni": sni_hostname,
        "version": tls_version_str
    }
