# NagraScout TPI project

## Guide d’installation et d’utilisation de l’outil
L’outil d’analyse a été conçu pour fonctionner sur une machine locale équipée de Python 3 et Wireshark (avec dumpcap). Il permet d’analyser un fichier de capture réseau (.pcap) afin d’en extraire des informations détaillées sur les appareils détectés, leur activité, les protocoles utilisés, les ports ouverts et les systèmes d’exploitation probables, ce qui nous permet d’avoir un fingerprint des appareils sur le réseau. Voici les étapes pour l’installer et l’utiliser :

### Prérequis
Avant toute chose, il faut s’assurer que l’environnement dispose des éléments suivants :
- Python 3.9 ou supérieur
- pip (gestionnaire de paquets Python)
- Un IDE pour ouvrir le projet et faciliter l’utilisation
- Les fichiers sources du projet (disponibles sur GitHub ou dans les annexes de ce rapport)
- Wireshark (avec dumpcap installé)

### Installation de l’outil
Il suffit de créer un dossier pour le projet, de l’ouvrir avec l’IDE, d’installer une extension de gestion git si ce n’est pas déjà fait puis de recopier ce lien pour récupérer le projet en local.

### Installation des dépendances
Depuis le dossier racine du projet, on peut installer les dépendances nécessaires via la commande suivante :
> pip install -r requirements.txt

### Récolte du PCAP
Première étape, l’analyse réseau. On va se connecter au réseau que l’on souhaite analyser, ensuite on a deux possibilités, soit se rendre sur Wireshark, et choisir Wi-Fi, on peut appliquer des filtres si nécessaire et lancer la capture, ou alors utiliser le script capture_script.py qui fait partie du projet, il ne permet cependant pas de préciser de filtre actuellement (v1.0). Si on utilise ce script, il est possible de préciser le temps de la capture en secondes.

Si on a lancé la capture avec l’interface Wireshark, il faut arrêter la capture et l’enregistrer de préférence dans le dossier src/capture/ du projet.

Ceci dit, si le script capture_script.py a été utilisé, il est possible de continuer sur l’analyse directement, le script de capture va alors exécuter le script parsing_script.py en lui donnant en entrée le pcap généré pendant la capture, ainsi pas besoin de s’embêter plus tard. Il en va de même pour la génération du HTML qui peut être lancée à la suite de celle du JSON.

### Analyse d’un PCAP
Pour lancer une analyse manuellement, il suffit d’exécuter le fichier parsing_script.py. Un explorateur de fichier s’ouvre pour permettre à l’utilisateur de sélectionner un fichier .pcap :
> python src/main/parsing_script.py

Une fois le fichier choisi, l’analyse se lance automatiquement. Une fois finie, un fichier .json est généré dans le dossier results/ Ce fichier contient toutes les informations extraites sous forme structurée.

### Génération du rapport HTML
Pour transformer ce fichier JSON en rapport propre ouvrable dans un navigateur :
> python src/report/generate_web_report.py

Ce script propose à l’utilisateur de choisir le fichier .json à convertir. Il génère ensuite un fichier .html dans le dossier results/ prêt à être ouvert.

### Fonctionnalités principales
- Détection des adresses IP (v4 et v6)
- Analyse des paquets ARP, DHCP, DNS, mDNS
- Empreinte TCP SYN et estimation du système d’exploitation
- Liste des ports TCP/UDP utilisés et leur protocole applicatif (HTTP, DNS, etc.)
- Liste des domaines contactés par chaque appareil
- Extraction des User-Agent HTTP et noms observés
- Visualisation lisible via un rapport HTML stylisé

Cet outil a été pensé pour être facilement portable, sans base de données ni serveur. Il est donc particulièrement adapté aux analyses rapides, à l’audit réseau local ou à un usage pédagogique.
 
