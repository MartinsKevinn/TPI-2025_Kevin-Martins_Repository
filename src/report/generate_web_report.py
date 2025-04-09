import json
from pathlib import Path
import tkinter as tk
from tkinter import filedialog
from collections import OrderedDict
import sys

if len(sys.argv) > 1:
        json_path = sys.argv[1]
else:
    # Fenêtre tkinter masquée
    root = tk.Tk()
    root.withdraw()
    print("📂 Sélectionnez le fichier .json à transformer")
    json_path = filedialog.askopenfilename(
        title="Choisissez un fichier JSON",
        filetypes=[("JSON files", "*.json"), ("Tous les fichiers", "*.*")]
    )
if not json_path:
    print("❌ Aucun fichier sélectionné. Conversion annulée.")
    exit(1)

with open(json_path, "r", encoding="utf-8") as f:
    data = json.load(f)

metadata = data.get("metadata", {})
devices = data.get("devices", [])

# Générer un HTML simple
html = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport d'analyse réseau</title>
    <style>
        body {{ font-family: Arial, sans-serif; padding: 20px; background-color: #f8f8f8; }}
        .device {{ border: 1px solid #ccc; padding: 15px; margin-bottom: 15px; background-color: white; border-radius: 8px; }}
        .device h2 {{ margin-top: 0; }}
        ul {{ padding-left: 20px; }}
        .meta {{ background-color: #e0e0e0; padding: 15px; border-radius: 8px; margin-bottom: 25px; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
        th, td {{ border: 1px solid #aaa; padding: 8px; text-align: left; }}
        th {{ background-color: #ddd; }}
        .proto-known {{background-color: #d9fdd3;}}
        table.tls {{background-color: #f9f9f9;}}
        .device-type {{font-weight: bold; color: #005a9c;}}
    </style>
</head>
<body>
    <h1>Rapport d'analyse réseau</h1>

    <div class="meta">
        <h3>Métadonnées de l'analyse</h3>
        <p><strong>Fichier analysé :</strong> {metadata.get("source_file", "Non spécifié")}</p>
        <p><strong>Début de capture :</strong> {metadata.get("capture_start", "Inconnu")}</p>
        <p><strong>Fin de capture :</strong> {metadata.get("capture_end", "Inconnu")}</p>
        <p><strong>Durée :</strong> {metadata.get("capture_duration_seconds", 0)} secondes</p>
        <p><strong>Note :</strong> {metadata.get("note")}</p>
        <p><strong>Paquets capturés :</strong> {metadata.get("packet_count")}</p>
        <p><strong>Paquets analysés :</strong> {metadata.get("used_packets")}</p>
        <p><strong>Version de l'outil :</strong> Scapy {metadata.get("scapy_version", "inconnue")}</p>
    </div>
"""

# Priorité d'affichage du nom

def determine_device_name(device):
    if device.get("hostname_from_dhcp"):
        return device["hostname_from_dhcp"]
    elif device.get("observed_hostnames"):
        return device["observed_hostnames"][0]
    elif device.get("arp_name_fallback"):
        return device["arp_name_fallback"]
    else:
        return "Nom inconnu"

for device in devices:
    html += f"""
    <div class="device">
        <h2>Appareil - {determine_device_name(device)} - {device.get("mac", "Inconnu")}</h2>
        <p><strong>Fabricant :</strong> {device.get("manufacturer", "Inconnu")}</p>
        <p class="device-type">Catégorie d'appareil estimée : {device.get("device_type", "Inconnue")}</p>
        <p><strong>IPv4 :</strong> {', '.join(device.get("ipv4_addresses", []))}</p>
        <p><strong>IPv6 :</strong> {', '.join(device.get("ipv6_addresses", []))}</p>
        <p><strong>ARP détecté :</strong> {'✅ Oui' if device.get('arp_detected') else '❌ Non'}</p>
    """
    # Section analyse ARP
    arp = device.get("arp_analysis", {})
    if arp:
        html += """
        <p><strong>Analyse comportementale ARP :</strong></p>
        <table>
            <tr><th>Comportement</th><th>Valeur</th></tr>
        """
        html += f"<tr><td>Appareil uniquement visible via ARP</td><td>{'✅' if arp.get('only_arp') else '❌'}</td></tr>"
        html += f"<tr><td>Appareil semble scanner le réseau</td><td>{'✅' if arp.get('acts_as_scanner') else '❌'}</td></tr>"
        html += f"<tr><td>Appareil recherché par d'autres</td><td>{'✅' if arp.get('targeted_by_others') else '❌'}</td></tr>"
        html += f"<tr><td>Appareil passif (pas de trafic visible, mais recherché)</td><td>{'✅' if arp.get('likely_passive') else '❌'}</td></tr>"
        if arp.get("requested_ips"):
            html += "<tr><td>IP ciblées par cet appareil</td><td>" + ", ".join(arp["requested_ips"]) + "</td></tr>"
        html += "</table>"

    html += f"""
        <p><strong>TCP SYN Fingerprints et système estimé :</strong></p>
        <table>
            <tr>
                <th>Fingerprint</th>
                <th>Estimation système</th>
            </tr>
            {''.join(
                f"<tr><td>{entry['fingerprint']}</td><td>{entry['os_guess']}</td></tr>"
                for entry in device.get('tcp_syn_analysis', [])
            ) or "<tr><td colspan='2'>Aucun</td></tr>"}
        </table>

        <p><strong>User-Agents :</strong></p>
        <ul>{"".join(f"<li>{ua}</li>" for ua in device.get("http_user_agents", [])) or "<li>Aucun</li>"}</ul>

        <p><strong>Services mDNS :</strong></p>
        <ul>{"".join(f"<li>{svc}</li>" for svc in device.get("mdns_services", [])) or "<li>Aucun</li>"}</ul>

        <p><strong>Noms observés :</strong></p>
        <ul>{"".join(f"<li>{hn}</li>" for hn in device.get("observed_hostnames", [])) or "<li>Aucun</li>"}</ul>

        <p><strong>Top 10 domaines contactés :</strong></p>
        <ul>
            {"".join(f"<li>{domain}</li>" for domain in device.get("top_domains_contacted", [])) or "<li>Aucun</li>"}
        </ul>

        <p><strong>Communications TLS détectées :</strong></p>
        <table class=table>
            <tr><th>Destination IP</th><th>SNI</th><th>Version TLS</th></tr>
            {''.join(
                f"<tr><td>{entry.get('dest_ip', 'Inconnu')}</td><td>{entry.get('sni', 'Inconnu')}</td><td>{entry.get('version', 'Inconnu')}</td></tr>"
                for entry in device.get("tls_communications", [])
            ) or "<tr><td colspan='3'>Aucune communication TLS détectée</td></tr>"}
        </table>

        <p><strong>Ports TCP détectés (protocole connu) :</strong></p>
        <table>
            <tr><th>Port</th><th>Protocole applicatif</th></tr>
            {''.join(
                f"<tr class='proto-known'><td>{port}</td><td>{proto}</td></tr>"
                for port, proto in device.get("protocols_ports", {}).get("TCP", [])
                if proto != "Inconnu"
            ) or "<tr><td colspan='2'>Aucun port connu</td></tr>"}
        </table>

        <p><strong>Ports UDP détectés (protocole connu) :</strong></p>
        <table>
            <tr><th>Port</th><th>Protocole applicatif</th></tr>
            {''.join(
                f"<tr class='proto-known'><td>{port}</td><td>{proto}</td></tr>"
                for port, proto in device.get("protocols_ports", {}).get("UDP", [])
                if proto != "Inconnu"
            ) or "<tr><td colspan='2'>Aucun port connu</td></tr>"}
        </table>

        <p><strong>Ports TCP sans protocole identifié :</strong></p>
        <ul>
    """
    unknown_tcp = [str(port) for port, app in device.get("protocols_ports", {}).get("TCP", []) if app == "Inconnu"]
    if unknown_tcp:
        html += f"<li>{'; '.join(sorted(unknown_tcp, key=int))}</li>"
    else:
        html += "<li>Aucun</li>"

    html += """
        </ul>
        <p><strong>Ports UDP sans protocole identifié :</strong></p>
        <ul>
    """
    unknown_udp = [str(port) for port, app in device.get("protocols_ports", {}).get("UDP", []) if app == "Inconnu"]
    if unknown_udp:
        html += f"<li>{'; '.join(sorted(unknown_udp, key=int))}</li>"
    else:
        html += "<li>Aucun</li>"

    html += """
        </ul>

        <p><strong>DHCP Info :</strong></p>
    """
    dhcp_entries = device.get("dhcp_info", [])
    unique_dhcp_entries = list({json.dumps(entry, sort_keys=True): entry for entry in dhcp_entries}.values())
    if dhcp_entries:
        all_keys = set()
        for entry in unique_dhcp_entries:
            all_keys.update(entry.keys())
        sorted_keys = sorted(all_keys)
        html += "<table><tr>" + "".join(f"<th>{key}</th>" for key in sorted_keys) + "</tr>"
        for entry in unique_dhcp_entries:
            html += "<tr>" + "".join(f"<td>{json.dumps(entry.get(key, ''), ensure_ascii=False)}</td>" for key in sorted_keys) + "</tr>"
        html += "</table>"
    else:
        html += "<p>Aucune information DHCP détectée.</p>"

    os_dhcp = device.get("os_guesses_dhcp", [])
    if os_dhcp:
        html += f"<p><strong>OS estimé depuis DHCP :</strong> {', '.join(os_dhcp)}</p>"

    html += """
    </div>
    """

html += """
</body>
</html>
"""

output_name = Path(json_path).stem + "_web.html"
output_path = Path("results") / output_name
output_path.write_text(html, encoding="utf-8")

print(f"✅ Rapport HTML généré avec succès : {output_path}")
