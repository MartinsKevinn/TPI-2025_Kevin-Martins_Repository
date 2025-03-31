import json
from pathlib import Path

# Charger le fichier JSON
with open("results/rapport_analyse.json", "r", encoding="utf-8") as f:
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
        <p><strong>Version de l'outil :</strong> Scapy {metadata.get("scapy_version", "inconnue")}</p>
    </div>
"""

# Affichage des appareils
for device in devices:
    html += f"""
    <div class="device">
        <h2>Appareil - {device.get("mac", "Inconnu")}</h2>
        <p><strong>Fabricant :</strong> {device.get("manufacturer", "Inconnu")}</p>
        <p><strong>ARP détecté :</strong> {'✅ Oui' if device.get('arp_detected') else '❌ Non'}</p>
        <p><strong>IPv4 :</strong> {', '.join(device.get("ipv4_addresses", []))}</p>
        <p><strong>IPv6 :</strong> {', '.join(device.get("ipv6_addresses", []))}</p>
        <p><strong>Type détecté :</strong> {device.get("possible_type", "Indéterminé")}</p>
        <p><strong>TCP SYN Fingerprints et système estimé :</strong></p>
        <table border="1" cellpadding="5" cellspacing="0">
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

        <p><strong>DHCP Info :</strong></p>
        <ul>
    """
    for entry in device.get("dhcp_info", []):
        html += f"<li><pre>{json.dumps(entry, indent=2, ensure_ascii=False)}</pre></li>"
    if not device.get("dhcp_info"):
        html += "<li>Aucune info DHCP</li>"

    html += """
        </ul>
    </div>
    """

html += """
</body>
</html>
"""

# Sauvegarder le fichier HTML
output_path = Path("results/rapport_web.html")
output_path.write_text(html, encoding="utf-8")

print(f"✅ Rapport HTML généré avec succès : {output_path}")
