#Modules externes
from scapy.all import rdpcap, DHCP, TCP, UDP, DNS, Raw, IP, IPv6, ARP
from datetime import datetime
import tkinter as tk
from tkinter import filedialog
from collections import Counter
import json
import sys
import os
import time
import scapy
import socket
import ipaddress
import subprocess

#Modules internes
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'report')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'utils')))
from generate_json_report import export_json
from port_mapping import PORT_APP_MAPPING
from tls_analysis import extract_tls_info
from oui_lookup import load_oui_database
from tcp_fingerprint_script import enrich_devices_with_os_guess



def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

#Fonction pour tenter de donner un indice sur le type de device dans le résultat en fonction des données récupérees
def guess_device_type(device):
    hostname = device.get("hostname_from_dhcp", "").lower()
    manufacturer = device.get("manufacturer", "").lower()
    user_agents = " ".join(device.get("http_user_agents", [])).lower()
    mdns = " ".join(device.get("mdns_services", [])).lower()

    if "ipad" in hostname:
        return "Tablette, Apple iPad"
    if "iphone" in hostname:
        return "Smartphone, Apple iPhone"
    if "appletv" in hostname:
        return "Box, Apple TV"
    if "apple" in manufacturer:
        return "Produit Apple"
    if "android" in hostname or "android" in user_agents:
        return "Smartphone, Android"
    if "macbook" in hostname or "mac" in user_agents:
        return "PC, Apple Macbook"
    if "windows" in user_agents or "desktop" in hostname or "laptop" in hostname:
        return "PC, Windows"
    if "appletv" in hostname:
        return "Box, Apple TV"
    if "sunrisetv" in hostname:
        return "Box, Sunrise"
    if "swisscom" in hostname:
        return "Box, Swisscom"
    if "nvidia" in manufacturer and "shield" in mdns:
        return "Box, NVIDIA Shield"
    if any(m in manufacturer for m in ["epson", "canon", "brother", "hp"]) or "printer" in hostname:
        return "Imprimante"
    if "philips lightning" in manufacturer:
        return "Pont Philips Hue"
    if "raspberry pi" in manufacturer:
        return "Raspberry Pi"
    if "tv" in hostname or "smarttv" in user_agents or any(m in manufacturer for m in ["samsung", "lg", "philips", "panasonic"]):
        return "Probablement une TV connectée"
    if "nas" in hostname or "synology" in manufacturer or "qnap" in manufacturer:
        return "NAS"
    if "router" in hostname or "gateway" in hostname or "asustek" in manufacturer:
        return "Routeur"
    if "cast" in hostname:
        return "Appareil qui fait effet Google Chromecast"
    
    if device.get("arp_analysis", {}).get("only_arp"):
        return "Appareil muet (ARP uniquement – souvent passif ou caché)"
    if device.get("arp_analysis", {}).get("acts_as_scanner"):
        return "Appareil actif – scan réseau via ARP"

    # 🔍 Si rien de tout ça : tenter de déterminer si c'est un mobile silencieux
    if (
        not device.get("http_user_agents") and
        not any("vendor_class_id" in entry or "hostname" in entry for entry in device.get("dhcp_info", [])) and
        not device.get("observed_hostnames") and
        len(device.get("mdns_services", [])) <= 2 and
        (len(device.get("ports_tcp", [])) + len(device.get("ports_udp", []))) <= 3
    ):
        return "Peu de données, donc probablement un appareil mobile (smartphone, tablette, etc.)"

    return "Inconnu"



def parse_pcap(file_path, oui_db):
    packets = rdpcap(file_path)
    used_packets = 0

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
        
        #incrémentation de used_packets si un paquet correspond à ceux qui vont être analysés
        if (
            pkt.haslayer(DHCP) or pkt.haslayer(ARP) or pkt.haslayer(DNS) or
            pkt.haslayer(Raw) or pkt.haslayer(TCP) or pkt.haslayer(UDP)
        ):
            used_packets += 1


        if src_mac:
            if src_mac not in devices_by_mac:
                mac_prefix = src_mac.lower()[0:8]
                manufacturer_lookup = oui_db.get(mac_prefix, 'Inconnu')
                devices_by_mac[src_mac] = {
                    "mac": src_mac,
                    "manufacturer": manufacturer_lookup,
                    "ipv4_addresses": set(),
                    "ipv6_addresses": set(),
                    "http_user_agents": set(),
                    "dhcp_info": [],
                    "mdns_services": set(),
                    "observed_hostnames": set(),
                    "tcp_syn_fingerprints": set(),
                    "domain_contact_counter": {},
                    "protocols_ports": {},
                    "arp_observations": []
                }

            device = devices_by_mac[src_mac]





            #IPv4
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





            #IPv6
            if pkt.haslayer(IPv6):
                device["ipv6_addresses"].add(pkt[IPv6].src)





            #DHCP
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

                #Extraction hostname
                hostname_dhcp = dhcp_info.get("hostname")
                if hostname_dhcp:
                    device["hostname_from_dhcp"] = hostname_dhcp

                # Analyse du vendor_class_id pour supposer l'OS (à prendre avec précaution)
                vendor_class_id = dhcp_info.get("vendor_class_id")
                param_req_list = dhcp_info.get("param_req_list", [])

                os_from_dhcp = None

                if vendor_class_id:
                    vendor_class_id = str(vendor_class_id).upper()
                    if "MSFT" in vendor_class_id:
                        if "5.0" in vendor_class_id:
                            os_from_dhcp = "Système Windows (MSFT 5.0 – XP ou plus récent)"
                        elif "7.0" in vendor_class_id:
                            os_from_dhcp = "Système Windows (MSFT 7.0 – probablement Win 7/10/11)"
                        else:
                            os_from_dhcp = "Système Windows (version inconnue)"
                    elif "ANDROID" in vendor_class_id:
                        os_from_dhcp = "Système Android"
                    elif "APPLE" in vendor_class_id or "MACOS" in vendor_class_id:
                        os_from_dhcp = "Apple macOS ou iOS"
                    elif "CHROME" in vendor_class_id:
                        os_from_dhcp = "Chrome OS"
                    elif "UBUNTU" in vendor_class_id:
                        os_from_dhcp = "Linux (Ubuntu)"
                    elif "LINUX" in vendor_class_id:
                        os_from_dhcp = "Système Linux (générique)"
                    elif "PXE" in vendor_class_id:
                        os_from_dhcp = "Client de boot réseau (PXE)"

                #Analyse complémentaire avec param_req_list
                #Exemple de signature typique : [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 121]
                if not os_from_dhcp:
                    if 121 in param_req_list and 119 in param_req_list and 252 in param_req_list:
                        os_from_dhcp = "Probablement un système Windows récent"
                    elif 95 in param_req_list and 114 in param_req_list:
                        os_from_dhcp = "Probablement un système Apple"
                    elif 12 in param_req_list and 15 in param_req_list and 6 in param_req_list:
                        os_from_dhcp = "Système client générique (DHCP standard)"

                # Ajout dans les données de l'appareil si une estimation a été trouvée
                if os_from_dhcp:
                    device.setdefault("os_guesses_dhcp", set()).add(os_from_dhcp)





            #TCP / UDP ports
            if pkt.haslayer(TCP):
                device["protocols_ports"].setdefault("TCP", set()).update([pkt[TCP].sport, pkt[TCP].dport])
            elif pkt.haslayer(UDP):
                device["protocols_ports"].setdefault("UDP", set()).update([pkt[UDP].sport, pkt[UDP].dport])





            #TCP SYN
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





            #HTTP User Agent
            if pkt.haslayer(Raw) and b"User-Agent" in pkt[Raw].load:
                raw_data = pkt[Raw].load.decode(errors="ignore")
                for line in raw_data.split("\\r\\n"):
                    if line.startswith("User-Agent:"):
                        device["http_user_agents"].add(line.replace("User-Agent:", "").strip())





            #UDP - MDNS
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
                arp_name_hint = pkt.src if pkt.src != src_mac else None  # scapy peut donner un nom ici

                if src_mac not in devices_by_mac:
                    mac_prefix = src_mac.lower()[0:8]
                    manufacturer_lookup = oui_db.get(mac_prefix, 'Inconnu')
                    devices_by_mac[src_mac] = {
                        "mac": src_mac,
                        "manufacturer": manufacturer_lookup,
                        "ipv4_addresses": set(),
                        "ipv6_addresses": set(),
                        "http_user_agents": set(),
                        "dhcp_info": [],
                        "mdns_services": set(),
                        "observed_hostnames": set(),
                        "tcp_syn_fingerprints": set(),
                        "arp_detected": True,
                    }

                device = devices_by_mac[src_mac]
                # Déduction d'un nom via champ 'src' du paquet si le nom n'existe nulle part ailleurs
                if "hostname_from_dhcp" not in device and not device.get("observed_hostnames"):
                    if isinstance(pkt.src, str):
                        device["arp_name_fallback"] = pkt.src
                device["ipv4_addresses"].add(src_ip)
                device["arp_detected"] = True

                if arp_name_hint and isinstance(arp_name_hint, str) and arp_name_hint not in device["observed_hostnames"]:
                    device["observed_hostnames"].add(arp_name_hint)






            #DNS
            if pkt.haslayer(DNS):
                dns_layer = pkt[DNS]
                if dns_layer.qdcount > 0 and hasattr(dns_layer.qd, "qname"):
                    query = dns_layer.qd.qname.decode(errors="ignore").rstrip('.')
                    parts = query.split('.')
                    if len(parts) >= 2:
                        base_domain = ".".join(parts[-2:])
                        device["domain_contact_counter"][base_domain] = device["domain_contact_counter"].get(base_domain, 0) + 1





            #TLS
            tls_info = extract_tls_info(pkt)
            if tls_info:
                device.setdefault("tls_communications", []).append(tls_info)


    def enrich_with_arp_behavior(devices_by_mac, all_packets):
        arp_seen_targets = {}
        arp_requests_by_mac = {}

        for pkt in all_packets:
            if pkt.haslayer(ARP):
                src_mac = pkt[ARP].hwsrc
                dst_ip = pkt[ARP].pdst

                # Enregistrement des IP ciblées par ce MAC
                if src_mac not in arp_requests_by_mac:
                    arp_requests_by_mac[src_mac] = set()
                arp_requests_by_mac[src_mac].add(dst_ip)

                # Qui est recherché dans le réseau ?
                if dst_ip not in arp_seen_targets:
                    arp_seen_targets[dst_ip] = set()
                arp_seen_targets[dst_ip].add(src_mac)

        for mac, device in devices_by_mac.items():
            device["arp_analysis"] = {}

            #Est-ce que le device est seulement présent dans les pkts ARP ?
            has_traffic = (
                device.get("http_user_agents") or
                device.get("mdns_services") or
                device.get("ports_tcp") or
                device.get("ports_udp")
            )
            device["arp_analysis"]["only_arp"] = not bool(has_traffic)

            # Est-ce qu'il émet pleins de requêtes ARP ?
            requested_ips = arp_requests_by_mac.get(mac, set())
            device["arp_analysis"]["requested_ips"] = list(requested_ips)
            device["arp_analysis"]["acts_as_scanner"] = len(requested_ips) > 10  # valeur ajustable
            device["arp_analysis"]["arp_requested_count"] = len(requested_ips)

            # Est-il est souvent recherché ?
            times_targeted = sum([1 for targets in arp_seen_targets.values() if mac in targets])
            device["arp_analysis"]["targeted_by_others"] = times_targeted > 3  # ajustable
            device["arp_analysis"]["likely_passive"] = not has_traffic and times_targeted > 0


    #Nettoyage final (conversion en liste pour json)
    for device in devices_by_mac.values():
        device["ipv4_addresses"] = list(device["ipv4_addresses"])
        device["ipv6_addresses"] = list(device["ipv6_addresses"])
        device["http_user_agents"] = list(device["http_user_agents"])
        device["mdns_services"] = list(device["mdns_services"])
        device["observed_hostnames"] = list(device["observed_hostnames"])
        device["tcp_syn_fingerprints"] = list(device["tcp_syn_fingerprints"])
        device["os_guesses_dhcp"] = list(device.get("os_guesses_dhcp", []))
        device["device_type"] = guess_device_type(device)

        #Top domaines contactés
        domain_counts = Counter(device.get("domain_contact_counter", {}))
        device["top_domains_contacted"] = [domain for domain, _ in domain_counts.most_common(10)]
        device.pop("domain_contact_counter", None)

        #Ports par protocole avec application associée
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

        if "tls_communications" in device:
            seen = set()
            unique_tls = []
            for entry in device["tls_communications"]:
                key = (entry["dest_ip"], entry["sni"], entry["version"])
                if key not in seen:
                    seen.add(key)
                    unique_tls.append(entry)
            device["tls_communications"] = unique_tls

    enrich_with_arp_behavior(devices_by_mac, packets)
    enriched_devices = enrich_devices_with_os_guess(list(devices_by_mac.values()))

    return {
        "metadata": {
            "capture_start": capture_start_str,
            "capture_end": capture_end_str,
            "capture_duration_seconds": duration,
            "note": "Durée réelle estimée entre le 1er et le dernier paquet. Peut être plus courte que la durée de capture planifiée.",
            "packet_count": len(packets),
            "used_packets": used_packets,
            "source_file": file_path,
            "scapy_version": scapy.__version__
        },
        "devices": enriched_devices
    }

if __name__ == "__main__":
    oui_db = load_oui_database("src/utils/oui.csv")
    # Vérifier si un fichier .pcap est passé en argument
    if len(sys.argv) > 1:
        pcap_path = sys.argv[1]
    else:
        # Sinon, ouvrir le sélecteur de fichier
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

    #Génération HTML direct si nécessaire
    choice = input("Souhaitez-vous générer la version HTML du rapport maintenant ? (y/n) : ").strip().lower()

    if choice == "y":
        try:
            print("\n🧩 Génération du rapport HTML en cours...")
            subprocess.run(["python", "src/report/generate_web_report.py", output_file], check=True)
        except subprocess.CalledProcessError as e:
            print(f"❌ Erreur lors de la génération HTML : {e}")
    else:
        print("📄 Vous pourrez générer le rapport HTML plus tard avec generate_web_report.py")
