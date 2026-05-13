"""
Génère un certificat X.509 pour le serveur LDAP,
signé par notre Root CA (Phase 2.1).
"""
import datetime
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import ipaddress

CERTS_DIR = os.path.join(os.path.dirname(__file__), "certs")
CA_CERT_PATH    = os.path.join(CERTS_DIR, "ca_cert.pem")
CA_KEY_PATH     = os.path.join(CERTS_DIR, "ca_private_key.pem")
LDAP_CERT_PATH  = os.path.join(CERTS_DIR, "ldap_server_cert.pem")
LDAP_KEY_PATH   = os.path.join(CERTS_DIR, "ldap_server_key.pem")

# Charger le CA
with open(CA_CERT_PATH, "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

with open(CA_KEY_PATH, "rb") as f:
    ca_key = serialization.load_pem_private_key(f.read(), password=None)

# Générer la clé privée du serveur LDAP
ldap_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Créer le certificat LDAP
now = datetime.datetime.now(datetime.UTC)
subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ChatSec Corp"),
    x509.NameAttribute(NameOID.COMMON_NAME, "chatsec-ldap"),
])

ldap_cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(ca_cert.subject)
    .public_key(ldap_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + datetime.timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.DNSName("chatsec-ldap"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]),
        critical=False
    )
    .sign(ca_key, hashes.SHA256())
)

# Sauvegarder
with open(LDAP_KEY_PATH, "wb") as f:
    f.write(ldap_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))

with open(LDAP_CERT_PATH, "wb") as f:
    f.write(ldap_cert.public_bytes(serialization.Encoding.PEM))

print(f"[OK] Clé LDAP        : {LDAP_KEY_PATH}")
print(f"[OK] Certificat LDAP : {LDAP_CERT_PATH}")
print(f"[OK] Signé par       : {ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
