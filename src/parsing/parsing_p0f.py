import re
import json
from pathlib import Path

#Chemin vers les fichiers
input_fp_path = Path("src/utils/p0f.fp")
output_json_path = Path("src/utils/tcp_fingerprints_from_p0f.json")

#Regex pour capturer les lignes de label et sig
label_pattern = re.compile(r"label\s*=\s*(.+)")
sig_pattern = re.compile(r"sig\s*=\s*(.+)")

entries = []
current_label = None

def sanitize_pattern(pattern: str) -> str:
    #échappe les tirets sauf s'ils sont entre deux caractères (ex: a-z)
    return re.sub(r'(?<!\\)-', r'\-', pattern)

for line in input_fp_path.read_text(encoding="utf-8").splitlines():
    line = line.strip()

    if not line or line.startswith(";"):
        continue

    label_match = label_pattern.match(line)
    if label_match:
        current_label = label_match.group(1).strip()
        continue

    sig_match = sig_pattern.match(line)
    if sig_match and current_label:
        raw_sig = sig_match.group(1).strip()

        #Simplification du motif
        simplified = raw_sig.replace("*", ".*").replace(":", ",").lower()
        simplified = sanitize_pattern(simplified)

        try:
            #Vérifier que le motif est une regex valide
            re.compile(simplified)
            entries.append({
                "pattern": simplified,
                "os": current_label.split(":")[-1].strip(),
                "confidence": 70
            })
        except re.error:
            print(f"❌ Motif regex invalide ignoré : {simplified}")

#Sauvegarde
output_json_path.write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"✅ {len(entries)} empreintes enregistrées dans {output_json_path}")
