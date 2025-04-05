import re
import json
from pathlib import Path

# Chemin vers le fichier .fp original
input_fp_path = Path("src/utils/p0f.fp")
output_json_path = Path("src/utils/tcp_fingerprints_from_p0f.json")

# Regex pour capturer les lignes de label et sig
label_pattern = re.compile(r"label\s*=\s*(.+)")
sig_pattern = re.compile(r"sig\s*=\s*(.+)")

entries = []
current_label = None

for line in input_fp_path.read_text(encoding="utf-8").splitlines():
    line = line.strip()

    if not line or line.startswith(";"):
        continue  # Ignorer les commentaires et lignes vides

    label_match = label_pattern.match(line)
    if label_match:
        current_label = label_match.group(1).strip()
        continue

    sig_match = sig_pattern.match(line)
    if sig_match and current_label:
        sig = sig_match.group(1).strip()

        # Transformation simplifiée : extraire infos pertinentes
        # Le format de sig est trop complexe, on fait une version simplifiée
        # Pour la démonstration, on ne garde que certaines infos
        simplified = {
            "pattern": sig.replace("*", ".*").replace(":", ",").lower(),  # Expression régulière
            "os": current_label.split(":")[-1].strip(),
            "confidence": 70  # valeur par défaut, à ajuster si souhaité
        }
        entries.append(simplified)

# Sauvegarder au format JSON
output_json_path.write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8")

entries[:5]  # Afficher un échantillon pour vérifier
