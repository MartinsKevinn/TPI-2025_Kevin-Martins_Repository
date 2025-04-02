from scapy.all import rdpcap, DHCP, TCP, UDP, DNS, Raw, IP, IPv6, ARP
import json
from oui_lookup import load_oui_database
from tcp_fingerprint_script import enrich_devices_with_os_guess
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'report')))
from generate_json_report import export_json
import time
import scapy
from datetime import datetime
import socket
import ipaddress
import tkinter as tk
from tkinter import filedialog
from collections import Counter
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'utils')))
from port_mapping import PORT_APP_MAPPING


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
                    "tcp_syn_fingerprints": set(),
                    "domain_contact_counter": {},
                    "protocols_ports": {}  # {"TCP": set([80, 443, 8080]), "UDP": set([53, 5353])}
                }

            device = devices_by_mac[src_mac]

            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                device["ipv4_addresses"].add(src_ip)

                #TCP ports
                if pkt.haslayer(TCP):
                    sport = pkt[TCP].sport #ports de sortie (représentes les ports que l'appareil utilise en local pour donner l'accès à un service)
                    dport = pkt[TCP].dport #ports de destination (représentes les ports externes que l'appareil va contacter)
                    for port in (sport, dport):
                        proto = PORT_APP_MAPPING.get(port, "Inconnu")
                        if "ports_tcp" not in device:
                            device["ports_tcp"] = set()
                        device["ports_tcp"].add(f"{port}")

                #UDP ports
                if pkt.haslayer(UDP):
                    sport = pkt[UDP].sport #ports de sortie (représentes les ports que l'appareil utilise en local pour donner l'accès à un service)
                    dport = pkt[UDP].dport #ports de destination (représentes les ports externes que l'appareil va contacter)
                    for port in (sport, dport):
                        proto = PORT_APP_MAPPING.get(port, "Inconnu")
                        if "ports_udp" not in device:
                            device["ports_udp"] = set()
                        device["ports_udp"].add(f"{port}")

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
                #Extraire le hostname sil existe
                hostname_dhcp = dhcp_info.get("hostname")
                if hostname_dhcp:
                    device["hostname_from_dhcp"] = hostname_dhcp

            if pkt.haslayer(TCP):
                device["protocols_ports"].setdefault("TCP", set()).update([pkt[TCP].sport, pkt[TCP].dport])
            elif pkt.haslayer(UDP):
                device["protocols_ports"].setdefault("UDP", set()).update([pkt[UDP].sport, pkt[UDP].dport])


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
                print("→ Fingerprint capturé :", fingerprint)


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
                        "arp_detected": True  #flag spécial
                    }

                device = devices_by_mac[src_mac]
                device["ipv4_addresses"].add(src_ip)
                device["arp_detected"] = True  #au cas où le device existait déjà

            if pkt.haslayer(DNS):
                dns_layer = pkt[DNS]
                if dns_layer.qdcount > 0 and hasattr(dns_layer.qd, "qname"):
                    query = dns_layer.qd.qname.decode(errors="ignore").rstrip('.')
                    parts = query.split('.')
                    if len(parts) >= 2:
                        base_domain = ".".join(parts[-2:])
                        device["domain_contact_counter"][base_domain] = device["domain_contact_counter"].get(base_domain, 0) + 1


    for device in devices_by_mac.values():
        device["ipv4_addresses"] = list(device["ipv4_addresses"])
        device["ipv6_addresses"] = list(device["ipv6_addresses"])
        device["http_user_agents"] = list(device["http_user_agents"])
        device["mdns_services"] = list(device["mdns_services"])
        device["observed_hostnames"] = list(device["observed_hostnames"])
        device["tcp_syn_fingerprints"] = list(device["tcp_syn_fingerprints"])

        # 🔝 Top domaines contactés
        domain_counts = Counter(device.get("domain_contact_counter", {}))
        device["top_domains_contacted"] = [domain for domain, _ in domain_counts.most_common(10)]
        device.pop("domain_contact_counter", None)

        # ✅ Ports par protocole avec application associée
        protocols_ports_cleaned = {}
        for proto, port_set in device.get("protocols_ports", {}).items():
            cleaned_ports = []
            for port in port_set:
                app_name = PORT_APP_MAPPING.get(port, "Inconnu")
                cleaned_ports.append((port, app_name))
            protocols_ports_cleaned[proto] = sorted(cleaned_ports)
        device["protocols_ports"] = protocols_ports_cleaned

        # 🔧 Conversion en liste simple pour les tableaux si besoin
        device["ports_tcp"] = sorted(list(device.get("ports_tcp", [])))
        device["ports_udp"] = sorted(list(device.get("ports_udp", [])))




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
    # Fenêtre tkinter masquée
    root = tk.Tk()
    root.withdraw()
    print("📂 Sélectionnez un fichier .pcap à analyser")
    pcap_path = filedialog.askopenfilename(
        title="Choisissez un fichier PCAP",
        filetypes=[("PCAP files", "*.pcap"), ("Tous les fichiers", "*.*")]
    )

    if not pcap_path:
        print("❌ Aucun fichier sélectionné. Analyse annulée.")
        exit(1)

    parsed_data = parse_pcap(pcap_path, oui_db)

    output_file = export_json(parsed_data, pcap_path)
    print(f"✅ Analyse terminée. Rapport généré : {output_file}")

