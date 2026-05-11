import datetime
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class RootCA:
    def __init__(self):
        self.ca_private_key = None
        self.ca_cert = None
        # On définit le chemin de sortie de manière plus robuste
        self.cert_dir = os.path.join("server", "certs")

    def generate_root_ca(self):
        """Génère la clé privée et le certificat auto-signé de la Root CA."""
        # 1. Génération de la clé privée
        self.ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )

        # 2. Configuration de l'identité (Subject == Issuer pour un Root CA)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Paris"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ChatSec Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ChatSec Root CA"),
        ])

        # Utilisation de datetime.now(datetime.UTC) pour éviter les warnings
        now = datetime.datetime.now(datetime.UTC)

        # 3. Création du certificat
        self.ca_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.ca_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + datetime.timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(self.ca_private_key, hashes.SHA256())

        print("✅ Root CA générée avec succès.")
        self.save_ca()

    def save_ca(self):
        """Sauvegarde les fichiers sur le disque en créant le dossier si besoin."""
        # CRUCIAL : Crée le dossier server/certs s'il n'existe pas
        if not os.path.exists(self.cert_dir):
            os.makedirs(self.cert_dir)
            print(f"📁 Dossier créé : {self.cert_dir}")

        # Sauvegarde Clé Privée
        key_path = os.path.join(self.cert_dir, "ca_private_key.pem")
        with open(key_path, "wb") as f:
            f.write(self.ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Sauvegarde Certificat Public
        cert_path = os.path.join(self.cert_dir, "ca_cert.pem")
        with open(cert_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))
        
        print(f"💾 Fichiers sauvegardés dans {self.cert_dir}")

    def sign_client_csr(self, csr_bytes):
        """Prend une CSR (bytes) en entrée et retourne un certificat signé (bytes)."""
        # 1. Charger la CSR
        csr = x509.load_pem_x509_csr(csr_bytes)
        
        # 2. Vérifier la validité de la signature de la CSR elle-même
        if not csr.is_signature_valid:
            raise ValueError("La signature de la CSR est invalide.")

        # 3. Construire le certificat pour le client
        client_cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            self.ca_cert.subject # Le serveur est l'émetteur
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.UTC)
        ).not_valid_after(
            # Le certificat client est valable 1 an
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        ).sign(self.ca_private_key, hashes.SHA256())

        return client_cert.public_bytes(serialization.Encoding.PEM)

if __name__ == "__main__":
    ca = RootCA()
    ca.generate_root_ca()