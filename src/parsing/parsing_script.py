from scapy.all import rdpcap, DHCP, TCP, UDP, DNS, Raw, IP, IPv6, ARP
import json
from oui_lookup import load_oui_database
from tcp_fingerprint_script import enrich_devices_with_os_guess
import time
import scapy
from datetime import datetime
import socket
import ipaddress

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def parse_pcap(file_path, oui_db):
    packets = rdpcap(file_path)

    if packets:
        start_ts = float(packets[0].time)
        end_ts = float(packets[-1].time)
        duration = round(end_ts - start_ts, 3)

        capture_start_str = datetime.fromtimestamp(start_ts).strftime("%Y-%m-%d %H:%M:%S")
        capture_end_str = datetime.fromtimestamp(end_ts).strftime("%Y-%m-%d %H:%M:%S")
    else:
        capture_start_str = capture_end_str = "Inconnu"
        duration = 0.0

    devices_by_mac = {}

    for pkt in packets:
        src_mac = pkt.src if hasattr(pkt, 'src') else None

        if src_mac:
            if src_mac not in devices_by_mac:
                mac_prefix = src_mac.lower()[0:8]
                manufacturer_lookup = oui_db.get(mac_prefix, 'Inconnu')
                devices_by_mac[src_mac] = {
                    "mac": src_mac,
                    "manufacturer": manufacturer_lookup,
                    "ipv4_addresses": set(),
                    "ipv6_addresses": set(),
                    "possible_type": None,
                    "http_user_agents": set(),
                    "dhcp_info": [],
                    "mdns_services": set(),
                    "observed_hostnames": set(),
                    "tcp_syn_fingerprints": set()
                }

            device = devices_by_mac[src_mac]

            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                device["ipv4_addresses"].add(src_ip)

            if pkt.haslayer(IPv6):
                device["ipv6_addresses"].add(pkt[IPv6].src)

            if pkt.haslayer(DHCP):
                dhcp_info = {}
                for opt in pkt[DHCP].options:
                    if isinstance(opt, tuple):
                        key = opt[0]
                        value = opt[1]
                        if isinstance(value, bytes):
                            value = value.decode(errors="ignore")
                        dhcp_info[key] = value
                device["dhcp_info"].append(dhcp_info)

            if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
                tcp_options = pkt[TCP].options
                window_size = pkt[TCP].window
                mss = None
                opt_names = []

                for opt in tcp_options:
                    if isinstance(opt, tuple):
                        opt_names.append(opt[0])
                        if opt[0] == 'MSS':
                            mss = opt[1]

                fingerprint = f"W:{window_size},MSS:{mss},Opts:{'-'.join(opt_names)}"
                device["tcp_syn_fingerprints"].add(fingerprint)

            if pkt.haslayer(Raw) and b"User-Agent" in pkt[Raw].load:
                raw_data = pkt[Raw].load.decode(errors="ignore")
                for line in raw_data.split("\\r\\n"):
                    if line.startswith("User-Agent:"):
                        device["http_user_agents"].add(line.replace("User-Agent:", "").strip())

            if pkt.haslayer(UDP) and pkt[UDP].dport == 5353 and pkt.haslayer(DNS):
                dns_layer = pkt[DNS]
                if dns_layer.qdcount > 0 and hasattr(dns_layer.qd, "qname"):
                    query = dns_layer.qd.qname.decode(errors="ignore")
                    device["mdns_services"].add(query)
                    hostname = query.split("._")[0]
                    device["observed_hostnames"].add(hostname)

            if pkt.haslayer(ARP):
                src_ip = pkt[ARP].psrc
                src_mac = pkt[ARP].hwsrc

                if src_mac not in devices_by_mac:
                    mac_prefix = src_mac.lower()[0:8]
                    manufacturer_lookup = oui_db.get(mac_prefix, 'Inconnu')
                    devices_by_mac[src_mac] = {
                        "mac": src_mac,
                        "manufacturer": manufacturer_lookup,
                        "ipv4_addresses": set(),
                        "ipv6_addresses": set(),
                        "possible_type": None,
                        "http_user_agents": set(),
                        "dhcp_info": [],
                        "mdns_services": set(),
                        "observed_hostnames": set(),
                        "tcp_syn_fingerprints": set(),
                        "arp_detected": True  # ➕ flag spécial
                    }

                device = devices_by_mac[src_mac]
                device["ipv4_addresses"].add(src_ip)
                device["arp_detected"] = True  # au cas où le device existait déjà



    for device in devices_by_mac.values():
        device["ipv4_addresses"] = list(device["ipv4_addresses"])
        device["ipv6_addresses"] = list(device["ipv6_addresses"])
        device["http_user_agents"] = list(device["http_user_agents"])
        device["mdns_services"] = list(device["mdns_services"])
        device["observed_hostnames"] = list(device["observed_hostnames"])
        device["tcp_syn_fingerprints"] = list(device["tcp_syn_fingerprints"])

    enriched_devices = enrich_devices_with_os_guess(list(devices_by_mac.values()))

    return {
        "metadata": {
            "capture_start": capture_start_str,
            "capture_end": capture_end_str,
            "capture_duration_seconds": duration,
            "source_file": file_path,
            "scapy_version": scapy.__version__
        },
        "devices": enriched_devices
    }

if __name__ == "__main__":
    oui_db = load_oui_database("src/utils/oui.csv")
    pcap_path = "src/capture/capture26032025_1407.pcap"
    parsed_data = parse_pcap(pcap_path, oui_db)

    with open("results/rapport_analyse.json", "w", encoding="utf-8") as json_file:
        json.dump(parsed_data, json_file, indent=4, ensure_ascii=False)

    print("Analyse terminée. Rapport généré : results/rapport_analyse.json")

