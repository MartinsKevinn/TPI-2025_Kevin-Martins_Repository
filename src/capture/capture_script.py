import subprocess
import time
from datetime import datetime
from pathlib import Path

def list_interfaces():
    print("Interfaces détectées (via dumpcap) :\n")
    result = subprocess.run(["dumpcap", "-D"], capture_output=True, text=True)

    if result.returncode != 0:
        print("❌ dumpcap introuvable ou erreur.")
        print(result.stderr)
        return []

    lines = result.stdout.strip().splitlines()
    for line in lines:
        print(line)
    return lines

def choose_interface():
    try:
        index = int(input("\nEntrez le numéro de l'interface à utiliser : "))
        return index
    except ValueError:
        print("❌ Entrée invalide.")
        return None

def start_capture(interface_index, duration):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path("src/capture")
    output_dir.mkdir(parents=True, exist_ok=True)

    output_path = output_dir / f"capture_{timestamp}.pcap"
    print(f"\n⏳ Démarrage de la capture pendant {duration} secondes...")

    try:
        subprocess.run([
            "dumpcap",
            "-i", str(interface_index),
            "-a", f"duration:{duration}",
            "-w", str(output_path)
        ], check=True)
        print(f"\n✅ Capture terminée. Fichier enregistré : {output_path}")
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur pendant la capture : {e}")
    return str(output_path)

if __name__ == "__main__":
    interfaces = list_interfaces()
    if not interfaces:
        exit(1)

    idx = choose_interface()
    if idx is None:
        exit(1)

    try:
        duration = int(input("Durée de la capture (en secondes) (3600 pour 1 heure | 86400 pour 1 jour | 604800 pour 1 semaine) : "))
        output_file = start_capture(idx, duration)
    except ValueError:
        print("❌ Durée invalide.")

#Possibilité de lancer l'analyse direct
choice = input("Souhaitez-vous lancer l'analyse du fichier capturé maintenant ? (y/n) : ").strip().lower()

if choice == "y":
    print("Lancement de l'analyse...")
    try:
        subprocess.run(["python", "src/parsing/parsing_script.py", output_file], check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur lors de l'analyse : {e}")
else:
    print("ℹ️ Analyse non lancée. Vous pouvez l'exécuter plus tard avec parsing_script.py")
