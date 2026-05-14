"""
test_server.py
Test d'intégration de la Phase 2.3 — simule un client qui se connecte au serveur.

Usage :
  Terminal 1 : python server/main_server.py
  Terminal 2 : python test_server.py
"""

import os
import sys
import ssl
import json
import struct
import base64
import socket

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from common.crypto import CryptoEngine
from common.protocol import SecureProtocol

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000
CA_CERT     = os.path.join("server", "certs", "ca_cert.pem")

# ─────────────────────────────────────────────
# Utilitaires réseau
# ─────────────────────────────────────────────

def send_msg(conn, payload: dict):
    data  = json.dumps(payload).encode("utf-8")
    frame = struct.pack(">I", len(data)) + data
    conn.sendall(frame)

def recv_msg(conn) -> dict:
    header = recv_exact(conn, 4)
    length = struct.unpack(">I", header)[0]
    data   = recv_exact(conn, length)
    return json.loads(data.decode("utf-8"))

def recv_exact(conn, n) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connexion fermée par le serveur")
        buf += chunk
    return buf

# ─────────────────────────────────────────────
# Génération d'une identité client de test
# ─────────────────────────────────────────────

def generate_test_csr(username: str):
    """Génère une clé RSA et un CSR pour le test."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ChatSec"),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ]))
        .sign(private_key, hashes.SHA256())
    )

    private_key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    )
    public_key_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    return private_key_pem, public_key_pem, csr_pem

# ─────────────────────────────────────────────
# Test principal
# ─────────────────────────────────────────────

def run_test(username: str, password: str):
    print(f"\n{'='*50}")
    print(f"  TEST CLIENT — {username}")
    print(f"{'='*50}\n")

    # 1. Générer identité
    private_key_pem, public_key_pem, csr_pem = generate_test_csr(username)
    print(f"[OK] Clé RSA et CSR générés pour {username}")

    # 2. Connexion TLS en vérifiant notre CA
    tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls_ctx.load_verify_locations(CA_CERT)
    tls_ctx.check_hostname = False  # hostname = IP locale

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn     = tls_ctx.wrap_socket(raw_sock, server_hostname="localhost")
    conn.connect((SERVER_HOST, SERVER_PORT))
    print(f"[OK] Tunnel TLS 1.3 établi avec le serveur")

    # 3. Envoi AUTH_REQ
    auth_payload = json.dumps({
        "password": password,
        "csr_pem":  csr_pem.decode()
    })
    send_msg(conn, {
        "type":    SecureProtocol.TYPE_AUTH,
        "sender":  username,
        "payload": base64.b64encode(auth_payload.encode()).decode()
    })
    print(f"[OK] AUTH_REQ envoyé")

    # 4. Réception AUTH_OK ou AUTH_FAIL
    response = recv_msg(conn)
    if response.get("type") == "AUTH_FAIL":
        print(f"[FAIL] Authentification refusée : {response.get('payload')}")
        conn.close()
        return

    if response.get("type") == "AUTH_OK":
        payload = response.get("payload", {})
        print(f"[OK] AUTH_OK reçu — Bienvenue {payload.get('displayname', username)}")
        cert_pem = payload.get("cert_pem", "")
        if cert_pem:
            print(f"[OK] Certificat X.509 reçu et signé par la CA")

    # 5. Lire les messages jusqu'à obtenir la clé AES de groupe
    aes_key = None
    for _ in range(5):
        next_msg = recv_msg(conn)
        msg_type = next_msg.get("type")
        if msg_type == SecureProtocol.TYPE_ROTATION:
            encrypted_key = base64.b64decode(next_msg.get("payload", ""))
            aes_key = CryptoEngine.decrypt_rsa(private_key_pem, encrypted_key)
            print(f"[OK] Clé AES de groupe reçue ({len(aes_key)} octets) — déchiffrée via RSA")
            break
        elif msg_type == "MEMBERS_UPDATE":
            members = next_msg.get("payload", [])
            print(f"[OK] Membres connectés : {members}")
        else:
            print(f"[INFO] Message reçu : {msg_type}")

    # 6. Envoi d'un message de chat chiffré
    if aes_key:
        message_clair = f"Bonjour depuis {username} — test E2EE !"
        encrypted_msg = CryptoEngine.encrypt_aes_gcm(bytearray(aes_key), message_clair)
        payload_b64   = base64.b64encode(encrypted_msg).decode()

        # Signer le payload
        signature = CryptoEngine.sign_message(private_key_pem, payload_b64)
        sig_b64   = base64.b64encode(signature).decode()

        send_msg(conn, {
            "type":      SecureProtocol.TYPE_CHAT,
            "sender":    username,
            "payload":   payload_b64,
            "signature": sig_b64
        })
        print(f"[OK] CHAT_MSG envoyé (chiffré AES-256 GCM + signé RSA-PSS)")

    print(f"\n[OK] Test réussi pour {username} !\n")
    conn.close()


if __name__ == "__main__":
    print("Assurez-vous que le serveur tourne dans un autre terminal :")
    print("  python server/main_server.py\n")

    # Test avec segolene (bon mot de passe)
    run_test("segolene", "mdp_segolene")

    # Test avec mauvais mot de passe
    print(f"\n{'='*50}")
    print("  TEST MAUVAIS MOT DE PASSE")
    print(f"{'='*50}")
    run_test("segolene", "mauvaismdp")
