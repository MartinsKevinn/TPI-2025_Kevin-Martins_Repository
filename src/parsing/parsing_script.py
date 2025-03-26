from scapy.all import rdpcap, DHCP, TCP, UDP, DNS, Raw, IP, IPv6
import json
from oui_lookup import load_oui_database

def parse_pcap(file_path, oui_db):
    packets = rdpcap(file_path)

    devices_by_mac = {}

    for pkt in packets:
        # Récupérer IP et MAC si possible
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
                    "observed_hostnames": set()
                }

            device = devices_by_mac[src_mac]

            if pkt.haslayer(IP):
                device["ipv4_addresses"].add(pkt[IP].src)
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
                pass  # TCP SYN fingerprinting possible ici

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

    # Convertir les sets en listes
    for device in devices_by_mac.values():
        device["ipv4_addresses"] = list(device["ipv4_addresses"])
        device["ipv6_addresses"] = list(device["ipv6_addresses"])
        device["http_user_agents"] = list(device["http_user_agents"])
        device["mdns_services"] = list(device["mdns_services"])
        device["observed_hostnames"] = list(device["observed_hostnames"])

    return list(devices_by_mac.values())


if __name__ == "__main__":
    oui_db = load_oui_database("src/utils/oui.csv")
    pcap_path = "src/capture/capture26032025_1407.pcap"
    parsed_data = parse_pcap(pcap_path, oui_db)

    with open("results/rapport_analyse.json", "w", encoding="utf-8") as json_file:
        json.dump(parsed_data, json_file, indent=4, ensure_ascii=False)

    print("Analyse terminée. Rapport généré : results/rapport_analyse.json")