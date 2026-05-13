# session_pki.py - Enrôlement PKI côté client
# Auteur : Lauraine
# Tâche  : 3.1

import os
import sys

# On ajoute le dossier racine au chemin pour pouvoir importer config
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from common import config

# CHEMINS DE STOCKAGE DES CLÉS ET CERTIFICATS

# Dossier où on va stocker les clés et certificats du client
CLIENT_CERTS_DIR = os.path.join(os.path.dirname(__file__), "certs")

# Fichier de la clé privée du client (à ne JAMAIS partager)
CLIENT_KEY_PATH  = os.path.join(CLIENT_CERTS_DIR, "client_key.pem")

# Fichier du certificat signé par le serveur
CLIENT_CERT_PATH = os.path.join(CLIENT_CERTS_DIR, "client_cert.pem")

# Fichier du certificat de l'autorité (pour vérifier le serveur)
CA_CERT_PATH     = os.path.join(CLIENT_CERTS_DIR, "ca_cert.pem")


# ÉTAPE 1 — GÉNÉRER LA PAIRE DE CLÉS RSA

def generer_cle_privee():
    """
    Génère une paire de clés RSA-4096.
    La clé privée est sauvegardée sur le disque.
    Retourne la clé privée.
    """
    print("[PKI] Génération de la paire de clés RSA-4096...")

    # Générer la clé privée RSA
    # public_exponent=65537 c'est la valeur standard recommandée
    # key_size=4096 c'est la taille demandée dans le cahier des charges
    cle_privee = rsa.generate_private_key(
        public_exponent=65537,
        key_size=config.RSA_KEY_SIZE  # 4096 défini dans config.py
    )

    # Créer le dossier client/certs s'il n'existe pas
    if not os.path.exists(CLIENT_CERTS_DIR):
        os.makedirs(CLIENT_CERTS_DIR)
        print(f"[PKI] Dossier créé : {CLIENT_CERTS_DIR}")

    # Sauvegarder la clé privée sur le disque
    # NoEncryption() = pas de mot de passe sur le fichier
    # (en production on mettrait un mot de passe)
    with open(CLIENT_KEY_PATH, "wb") as f:
        f.write(cle_privee.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    print(f"[PKI] Clé privée sauvegardée : {CLIENT_KEY_PATH}")
    return cle_privee


# ÉTAPE 2 — CRÉER UNE CSR


def creer_csr(username, cle_privee):
    """
    Crée une CSR (Certificate Signing Request) = demande de certificat.
    C'est comme remplir un formulaire de demande de carte d'identité.

    Args:
        username   : le nom de l'utilisateur (ex: "lauraine")
        cle_privee : la clé privée générée à l'étape 1

    Retourne la CSR en bytes (format PEM).
    """
    print(f"[PKI] Création de la CSR pour {username}...")

    # Construire l'identité qui sera dans le certificat
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ChatSec Corp"),
        # Le Common Name = le nom d'utilisateur, c'est ce que le serveur lit
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])).sign(cle_privee, hashes.SHA256())
    # On signe la CSR avec notre clé privée pour prouver qu'on la possède

    csr_bytes = csr.public_bytes(serialization.Encoding.PEM)
    print("[PKI] CSR créée avec succès")
    return csr_bytes


# ÉTAPE 3 — SAUVEGARDER LE CERTIFICAT REÇU


def sauvegarder_certificat(cert_bytes):
    """
    Sauvegarde le certificat signé reçu du serveur sur le disque.

    Args:
        cert_bytes : le certificat en bytes (format PEM) reçu du serveur
    """
    # Créer le dossier si besoin
    if not os.path.exists(CLIENT_CERTS_DIR):
        os.makedirs(CLIENT_CERTS_DIR)

    with open(CLIENT_CERT_PATH, "wb") as f:
        f.write(cert_bytes)

    print(f"[PKI] Certificat sauvegardé : {CLIENT_CERT_PATH}")


# ÉTAPE 4 — CHARGER LA CLÉ ET LE CERTIFICAT


def charger_credentials():
    """
    Charge la clé privée et le certificat depuis le disque.
    Appelée au démarrage si l'utilisateur a déjà été enrôlé.

    Retourne (cle_privee, certificat) ou (None, None) si pas encore enrôlé.
    """
    if not os.path.exists(CLIENT_KEY_PATH) or not os.path.exists(CLIENT_CERT_PATH):
        print("[PKI] Aucun certificat trouvé — enrôlement nécessaire.")
        return None, None

    # Charger la clé privée
    with open(CLIENT_KEY_PATH, "rb") as f:
        cle_privee = serialization.load_pem_private_key(f.read(), password=None)

    # Charger le certificat
    with open(CLIENT_CERT_PATH, "rb") as f:
        certificat = x509.load_pem_x509_certificate(f.read())

    print("[PKI] Credentials chargés depuis le disque ✓")
    return cle_privee, certificat



# ÉTAPE 5 — ENRÔLEMENT (fonction principale)


def enroler_client(username, connexion_serveur=None):
    """
    Fonction principale : gère tout le processus d'enrôlement PKI.

    Si l'utilisateur a déjà un certificat → on le charge.
    Sinon → on génère les clés, on crée la CSR, on l'envoie au serveur.

    Args:
        username          : nom de l'utilisateur
        connexion_serveur : la connexion réseau vers le serveur (None pour tests)

    Retourne (cle_privee, certificat)
    """
    # Vérifier si déjà enrôlé
    cle_privee, certificat = charger_credentials()
    if cle_privee and certificat:
        print(f"[PKI] {username} déjà enrôlé ")
        return cle_privee, certificat

    # Pas encore enrôlé → processus complet
    print(f"[PKI] Début de l'enrôlement pour {username}...")

    # Étape 1 : Générer les clés
    cle_privee = generer_cle_privee()

    # Étape 2 : Créer la CSR
    csr_bytes = creer_csr(username, cle_privee)

    # Étape 3 : Envoyer la CSR au serveur et recevoir le certificat
    if connexion_serveur:
        # En situation réelle : envoyer via le réseau
        # connexion_serveur.send(csr_bytes)
        # cert_bytes = connexion_serveur.recv(4096)
        pass
    else:
        # Mode test : on simule la réponse du serveur
        # On utilise ca_manager  ferait le serveur
        print("[PKI] Mode test — simulation de la signature par le serveur...")
        sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
        from server.pki.ca_manager import RootCA
        ca = RootCA()
        ca.generate_root_ca()
        cert_bytes = ca.sign_client_csr(csr_bytes)

    # Étape 4 : Sauvegarder le certificat
    sauvegarder_certificat(cert_bytes)

    # Recharger depuis le disque
    cle_privee, certificat = charger_credentials()
    print(f"[PKI] Enrôlement de {username} terminé avec succès")
    return cle_privee, certificat


# TEST 


if __name__ == "__main__":
    cle, cert = enroler_client("lauraine")
    if cert:
        print(f"\n[PKI] Certificat valide jusqu'au : {cert.not_valid_after_utc}")
        print(f"[PKI] Émis pour : {cert.subject}")