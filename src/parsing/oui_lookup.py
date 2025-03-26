# oui_lookup.py — Module de chargement et normalisation de la base OUI

import csv

def normalize_oui_prefix(assignment):
    """Convertit un préfixe OUI au format 'C87F54' en 'c8:7f:54'"""
    return ':'.join(assignment[i:i+2] for i in range(0, 6, 2)).lower()

def load_oui_database(filepath):
    oui_db = {}
    with open(filepath, 'r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            prefix = normalize_oui_prefix(row['Assignment'])
            oui_db[prefix] = row['Organization Name']
    return oui_db

