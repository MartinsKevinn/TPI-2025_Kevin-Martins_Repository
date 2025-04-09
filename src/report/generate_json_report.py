import json
import os
from datetime import datetime

def export_json(data, source_pcap_path, output_dir="results"):
    os.makedirs(output_dir, exist_ok=True)

    capture_start_str = data.get("metadata", {}).get("capture_start", "")
    try:
        timestamp = datetime.strptime(capture_start_str, "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d_%H-%M-%S")
    except Exception:
        #fallback au timestamp actuel en cas d'erreur
        timestamp = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
        print("Pas de timestamp dans le fichier pcap, utilisation de la date actuelle pour la génération du JSON !")

    basename = os.path.basename(source_pcap_path)
    name_without_ext = os.path.splitext(basename)[0]

    output_filename = f"{output_dir}/rapport_{name_without_ext}_{timestamp}.json"

    with open(output_filename, "w", encoding="utf-8") as json_file:
        json.dump(data, json_file, indent=4, ensure_ascii=False)

    return output_filename
