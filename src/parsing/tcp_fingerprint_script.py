import json
import re
from pathlib import Path

#Chargement de la base de données d'empreintes
def load_fingerprint_database(json_path="src/utils/tcp_fingerprints_from_p0f.json"):
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)

FINGERPRINT_DB = load_fingerprint_database()

#Motifs typiques mais non identifiés dans la base principale
TYPICAL_UNKNOWN = [
    {
        "pattern": r"W:5840,MSS:1460",
        "description": "Typique Linux sans WScale"
    },
    {
        "pattern": r"W:14600,MSS:1460",
        "description": "Observé sur certains routeurs ou imprimantes réseau"
    }
]

def identify_os_from_fingerprint(fingerprint: str) -> dict:
    for entry in FINGERPRINT_DB:
        pattern = entry["pattern"]

        #Ignorer les motifs simples qui ne sont que des MTU (ex: "1450")
        if re.fullmatch(r"\d{3,5}", pattern):
            continue

        if re.search(pattern, fingerprint):
            return {
                "os_guess": entry["os"],
                "confidence": entry["confidence"]
            }

    # Cas de motifs typiques non classifiés
    for entry in TYPICAL_UNKNOWN:
        if re.search(entry["pattern"], fingerprint):
            return {
                "os_guess": "Inconnu mais typique",
                "confidence": 50,
                "notes": entry["description"]
            }

    #Si rien ne correspond
    return {
        "os_guess": "Système inconnu",
        "confidence": 0
    }

def enrich_devices_with_os_guess(devices: list) -> list:
    for device in devices:
        device["tcp_syn_analysis"] = []
        for fp in device.get("tcp_syn_fingerprints", []):
            result = identify_os_from_fingerprint(fp)
            device["tcp_syn_analysis"].append({
                "fingerprint": fp,
                **result
            })
    return devices

#Test direct
if __name__ == "__main__":
    test_devices = [
        {
            "mac": "00:11:22:33:44:55",
            "tcp_syn_fingerprints": [
                "W:65535,MSS:1460,Opts:MSS-NOP-WScale-NOP-NOP-SAckOK",
                "W:5840,MSS:1460,Opts:MSS-NOP"
            ]
        }
    ]

    enriched = enrich_devices_with_os_guess(test_devices)
    print(json.dumps(enriched, indent=2, ensure_ascii=False))
