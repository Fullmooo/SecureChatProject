# ============================================================
# session_pki.py - Enrolement PKI cote client
# Auteur : Lauraine
# Tache  : 3.1
# ============================================================

import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from common import config

# CHEMINS DE STOCKAGE

CLIENT_CERTS_DIR = os.path.join(os.path.dirname(__file__), "certs")
CLIENT_KEY_PATH  = os.path.join(CLIENT_CERTS_DIR, "client_key.pem")
CLIENT_CERT_PATH = os.path.join(CLIENT_CERTS_DIR, "client_cert.pem")
CA_CERT_PATH     = os.path.join(CLIENT_CERTS_DIR, "ca_cert.pem")


# ETAPE 1 - GENERER LA PAIRE DE CLES RSA

def generer_cle_privee():
    """
    Genere une paire de cles RSA-4096.
    La cle privee est sauvegardee sur le disque.
    Retourne la cle privee.
    """
    print("[PKI] Generation de la paire de cles RSA-4096...")

    cle_privee = rsa.generate_private_key(
        public_exponent=65537,
        key_size=config.RSA_KEY_SIZE
    )

    if not os.path.exists(CLIENT_CERTS_DIR):
        os.makedirs(CLIENT_CERTS_DIR)
        print(f"[PKI] Dossier cree : {CLIENT_CERTS_DIR}")

    # TODO : chiffrer avec mot de passe LDAP quand Phase 3.2 sera disponible
    with open(CLIENT_KEY_PATH, "wb") as f:
        f.write(cle_privee.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    print(f"[PKI] Cle privee sauvegardee : {CLIENT_KEY_PATH}")
    return cle_privee


# ETAPE 2 - CREER UNE CSR

def creer_csr(username, cle_privee):
    """
    Cree une CSR (Certificate Signing Request).
    C'est la demande de certificat envoyee au serveur.

    Args:
        username   : nom de l'utilisateur (ex: "lauraine")
        cle_privee : cle privee generee a l'etape 1

    Retourne la CSR en bytes (format PEM).
    """
    print(f"[PKI] Creation de la CSR pour {username}...")

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ChatSec Corp"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])).sign(cle_privee, hashes.SHA256())

    csr_bytes = csr.public_bytes(serialization.Encoding.PEM)
    print("[PKI] CSR creee avec succes")
    return csr_bytes


# ETAPE 3 - SAUVEGARDER LE CERTIFICAT RECU

def sauvegarder_certificat(cert_bytes):
    """
    Sauvegarde le certificat signe recu du serveur sur le disque.

    Args:
        cert_bytes : certificat en bytes (format PEM) recu du serveur
    """
    if not os.path.exists(CLIENT_CERTS_DIR):
        os.makedirs(CLIENT_CERTS_DIR)

    with open(CLIENT_CERT_PATH, "wb") as f:
        f.write(cert_bytes)

    print(f"[PKI] Certificat sauvegarde : {CLIENT_CERT_PATH}")


# ETAPE 4 - CHARGER LA CLE ET LE CERTIFICAT

def charger_credentials():
    """
    Charge la cle privee et le certificat depuis le disque.
    Appelee au demarrage si l'utilisateur a deja ete enrole.

    Retourne (cle_privee, certificat) ou (None, None) si pas encore enrole.
    """
    if not os.path.exists(CLIENT_KEY_PATH) or not os.path.exists(CLIENT_CERT_PATH):
        print("[PKI] Aucun certificat trouve - enrolement necessaire.")
        return None, None

    with open(CLIENT_KEY_PATH, "rb") as f:
        cle_privee = serialization.load_pem_private_key(f.read(), password=None)

    with open(CLIENT_CERT_PATH, "rb") as f:
        certificat = x509.load_pem_x509_certificate(f.read())

    print("[PKI] Credentials charges depuis le disque")
    return cle_privee, certificat


# ETAPE 5 - ENROLEMENT COMPLET (fonction principale)

def enroler_client(username, connexion_serveur=None):
    """
    Fonction principale : gere tout le processus d'enrolement PKI.

    Si l'utilisateur a deja un certificat -> on le charge.
    Sinon -> on genere les cles, on cree la CSR, on l'envoie au serveur.

    Args:
        username          : nom de l'utilisateur
        connexion_serveur : connexion reseau vers le serveur (None pour tests)

    Retourne (cle_privee, certificat)
    """
    # Verifier si deja enrole
    cle_privee, certificat = charger_credentials()
    if cle_privee and certificat:
        print(f"[PKI] {username} deja enrole")
        return cle_privee, certificat

    print(f"[PKI] Debut de l'enrolement pour {username}...")

    # Etape 1 : Generer les cles
    cle_privee = generer_cle_privee()

    # Etape 2 : Creer la CSR
    csr_bytes = creer_csr(username, cle_privee)

    # Etape 3 : Envoyer la CSR au serveur et recevoir le certificat
    if connexion_serveur:
        # TODO : a implementer quand Phase 3.2 (reseau TLS) sera disponible
        # connexion_serveur.send(csr_bytes)
        # cert_bytes = connexion_serveur.recv(4096)
        pass
    else:
        # Mode test : simulation de la reponse du serveur
        print("[PKI] Mode test - utilisation du CA existant...")
        from server.pki.ca_manager import RootCA
        ca = RootCA()

        ca_cert_path = os.path.join("server", "certs", "ca_cert.pem")
        ca_key_path  = os.path.join("server", "certs", "ca_private_key.pem")

        if os.path.exists(ca_cert_path) and os.path.exists(ca_key_path):
            # Le CA existe deja - on le charge sans l'ecraser
            with open(ca_cert_path, "rb") as f:
                ca.ca_cert = x509.load_pem_x509_certificate(f.read())
            with open(ca_key_path, "rb") as f:
                ca.ca_private_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )
            print("[PKI] CA existant charge avec succes.")
        else:
            # Premier lancement uniquement - pas de CA existant
            print("[PKI] Aucun CA trouve - creation d'un CA de test...")
            ca.generate_root_ca()

        cert_bytes = ca.sign_client_csr(csr_bytes)

    # Etape 4 : Sauvegarder le certificat
    sauvegarder_certificat(cert_bytes)

    # Recharger depuis le disque
    cle_privee, certificat = charger_credentials()
    print(f"[PKI] Enrolement de {username} termine avec succes")
    return cle_privee, certificat


# LANCEMENT DIRECT POUR TEST

if __name__ == "__main__":
    cle, cert = enroler_client("lauraine")
    if cert:
        print(f"\n[PKI] Certificat valide jusqu'au : {cert.not_valid_after_utc}")
        print(f"[PKI] Emis pour : {cert.subject}")