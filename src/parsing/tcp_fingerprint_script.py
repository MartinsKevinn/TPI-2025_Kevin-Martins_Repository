def identify_os_from_fingerprint(fingerprint: str) -> str:
    #Retourne une estimation du système à partir d'une empreinte TCP SYN simplifiée.
    if "MSS:1460" in fingerprint and "W:65535" in fingerprint:
        if "WScale" in fingerprint and "SAckOK" in fingerprint:
            if "NOP" in fingerprint:
                return "Probablement Windows (10/11)"
    
    if "MSS:1460" in fingerprint and "W:29200" in fingerprint:
        return "Probablement Linux"

    if "MSS:1380" in fingerprint or "MSS:1400" in fingerprint:
        return "Probablement Android"

    if "MSS:1460" in fingerprint and "W:8192" in fingerprint:
        return "Probablement macOS"

    if "MSS:1440" in fingerprint and "W:65535" in fingerprint:
        return "Windows en machine virtuelle ou avec VPN"

    return "Système inconnu"

def enrich_devices_with_os_guess(devices: list) -> list:
    for device in devices:
        device["tcp_syn_analysis"] = []
        for fp in device.get("tcp_syn_fingerprints", []):
            guess = identify_os_from_fingerprint(fp)
            device["tcp_syn_analysis"].append({
                "fingerprint": fp,
                "os_guess": guess
            })
    return devices


# Exemple d'utilisation directe
if __name__ == "__main__":
    test_devices = [
        {
            "mac": "00:11:22:33:44:55",
            "tcp_syn_fingerprints": [
                "W:65535,MSS:1460,Opts:MSS-NOP-WScale-NOP-NOP-SAckOK",
                "W:65535,MSS:1440,Opts:MSS-NOP-WScale-NOP-NOP-SAckOK"
            ]
        }
    ]

    enriched = enrich_devices_with_os_guess(test_devices)
    for d in enriched:
        print(f"{d['mac']} → {d.get('os_guess')}")