# ============================================================
# config.py - Panneau de contrôle de l'application
# Auteur : Lauraine
# Tâche  : 1.1
# ============================================================

import os

# --- SERVEUR ---
# L'adresse IP du serveur (localhost = sur notre propre machine pour les tests)
SERVER_HOST = "127.0.0.1"

# Le port sur lequel le serveur écoute les connexions des clients
SERVER_PORT = 5000

# Le port LDAPS pour l'authentification (636 = port standard sécurisé)
LDAP_PORT = 636

# Délai maximum d'attente pour une connexion (en secondes)
TIMEOUT = 30

# --- CHEMINS VERS LES FICHIERS DE SÉCURITÉ ---
# Dossier de base du projet (le dossier où se trouve ce fichier)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Dossier qui contiendra les certificats et clés
CERTS_DIR = os.path.join(BASE_DIR, "certs")

# Fichier du certificat de l'Autorité de Certification (le serveur)
CA_CERT_PATH = os.path.join(CERTS_DIR, "ca_cert.pem")

# Fichier de la clé privée du client (à garder SECRET)
CLIENT_KEY_PATH = os.path.join(CERTS_DIR, "client_key.pem")

# Fichier du certificat du client (sa carte d'identité numérique)
CLIENT_CERT_PATH = os.path.join(CERTS_DIR, "client_cert.pem")

# --- CRYPTOGRAPHIE ---
# Taille de la clé RSA en bits (4096 = très sécurisé)
RSA_KEY_SIZE = 4096

# Algorithme de chiffrement symétrique utilisé pour les messages
AES_KEY_SIZE = 256

# --- BASE DE DONNÉES LOCALE ---
# Chemin vers la base SQLite qui stocke l'historique des messages
DB_PATH = os.path.join(BASE_DIR, "messages.db")

# --- FONCTION DE VALIDATION ---
def valider_config():
    """
    Vérifie que la configuration est correcte au démarrage.
    Retourne True si tout est ok, lève une erreur sinon.
    """
    # Vérifier que le port est un nombre valide (entre 1 et 65535)
    if not (1 <= SERVER_PORT <= 65535):
        raise ValueError(f"Port invalide : {SERVER_PORT}. Doit être entre 1 et 65535.")

    # Vérifier que le timeout est positif
    if TIMEOUT <= 0:
        raise ValueError(f"Timeout invalide : {TIMEOUT}. Doit être positif.")

    # Créer le dossier certs s'il n'existe pas encore
    if not os.path.exists(CERTS_DIR):
        os.makedirs(CERTS_DIR)
        print(f"[CONFIG] Dossier créé : {CERTS_DIR}")

    print("[CONFIG] Configuration validée avec succès ✓")
    return True


# Ce bloc s'exécute uniquement si on lance ce fichier directement
# (pas quand un autre fichier l'importe)
if __name__ == "__main__":
    valider_config()
    print(f"Serveur      : {SERVER_HOST}:{SERVER_PORT}")
    print(f"LDAP port    : {LDAP_PORT}")
    print(f"Clé RSA      : {RSA_KEY_SIZE} bits")
    print(f"Dossier certs: {CERTS_DIR}")