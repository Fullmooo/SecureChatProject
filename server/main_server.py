"""
server/main_server.py
Phase 2.3 — Moteur Réseau Multithread

Rôle : Serveur TCP/TLS 1.3 qui gère les connexions des clients,
       authentifie via LDAP, signe les CSR, distribue la clé AES
       de groupe et relaie les messages chiffrés.
"""

import os
import sys
import ssl
import json
import time
import struct
import base64
import socket
import logging
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from common.crypto import CryptoEngine
from common.protocol import SecureProtocol
from server.ldap_auth import authenticate_user, list_users
from server.pki.ca_manager import RootCA

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

SERVER_HOST          = "0.0.0.0"
SERVER_PORT          = 5000
CERTS_DIR            = os.path.join(os.path.dirname(__file__), "certs")
KEY_ROTATION_HOURS   = 24
LDAP_CHECK_SECONDS   = 30

logging.basicConfig(
    level=logging.INFO,
    format="[SERVER] %(asctime)s — %(levelname)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("server")


# ─────────────────────────────────────────────
# SESSION CLIENT
# ─────────────────────────────────────────────

class ClientSession:
    """Représente un client connecté et authentifié."""

    def __init__(self, username: str, conn: ssl.SSLSocket,
                 public_key_pem: bytes, cert_pem: bytes):
        self.username       = username
        self.conn           = conn
        self.public_key_pem = public_key_pem
        self.cert_pem       = cert_pem
        self.send_lock      = threading.Lock()


# ─────────────────────────────────────────────
# SERVEUR PRINCIPAL
# ─────────────────────────────────────────────

class SecureChatServer:

    def __init__(self):
        self.clients      : dict[str, ClientSession] = {}
        self.clients_lock = threading.Lock()
        self.group_key    = bytearray(os.urandom(32))  # AES-256 en RAM uniquement
        self.key_lock     = threading.Lock()
        self.stop_event   = threading.Event()

        self._load_pki()
        self._setup_tls()
        logger.info("Serveur initialisé — PKI et TLS 1.3 chargés")

    # ── Initialisation ───────────────────────────────────────────────────────

    def _load_pki(self):
        """Charge le Root CA pour signer les CSR clients."""
        self.ca = RootCA()
        with open(os.path.join(CERTS_DIR, "ca_cert.pem"), "rb") as f:
            self.ca.ca_cert = x509.load_pem_x509_certificate(f.read())
        with open(os.path.join(CERTS_DIR, "ca_private_key.pem"), "rb") as f:
            self.ca.ca_private_key = serialization.load_pem_private_key(
                f.read(), password=None
            )

    def _setup_tls(self):
        """Configure le contexte TLS 1.3 serveur."""
        self.tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self.tls_ctx.load_cert_chain(
            certfile=os.path.join(CERTS_DIR, "ca_cert.pem"),
            keyfile=os.path.join(CERTS_DIR, "ca_private_key.pem")
        )

    # ── Réseau : envoi / réception ────────────────────────────────────────────

    def _send(self, session: ClientSession, payload: dict):
        """Envoie un message JSON préfixé de sa taille (4 octets big-endian)."""
        data  = json.dumps(payload).encode("utf-8")
        frame = struct.pack(">I", len(data)) + data
        with session.send_lock:
            session.conn.sendall(frame)

    def _recv(self, conn: ssl.SSLSocket) -> dict | None:
        """Reçoit un message JSON complet depuis la connexion."""
        header = self._recv_exact(conn, 4)
        if not header:
            return None
        length = struct.unpack(">I", header)[0]
        data   = self._recv_exact(conn, length)
        if not data:
            return None
        return json.loads(data.decode("utf-8"))

    @staticmethod
    def _recv_exact(conn: ssl.SSLSocket, n: int) -> bytes | None:
        """Lit exactement n octets depuis le socket."""
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    # ── Gestion de la clé AES de groupe ──────────────────────────────────────

    def _send_group_key(self, session: ClientSession):
        """Envoie la clé AES de groupe chiffrée en RSA au client."""
        with self.key_lock:
            key_bytes = bytes(self.group_key)

        encrypted_key = CryptoEngine.encrypt_rsa(session.public_key_pem, key_bytes)
        self._send(session, {
            "type":    SecureProtocol.TYPE_ROTATION,
            "sender":  "SERVER",
            "payload": base64.b64encode(encrypted_key).decode()
        })
        logger.info(f"Clé AES envoyée à {session.username}")

    def _rotate_group_key(self, reason: str = "rotation automatique"):
        """Génère une nouvelle clé AES et la redistribue à tous les clients."""
        logger.info(f"Rotation de clé — {reason}")
        with self.key_lock:
            CryptoEngine.secure_wipe(self.group_key)
            self.group_key = bytearray(os.urandom(32))

        with self.clients_lock:
            sessions = list(self.clients.values())

        for session in sessions:
            try:
                self._send_group_key(session)
            except Exception as e:
                logger.warning(f"Erreur envoi clé à {session.username}: {e}")

    # ── Broadcast ─────────────────────────────────────────────────────────────

    def _broadcast(self, message: dict, exclude: str = None):
        """Envoie un message à tous les clients connectés sauf l'exclu."""
        with self.clients_lock:
            targets = list(self.clients.values())

        for session in targets:
            if session.username == exclude:
                continue
            try:
                self._send(session, message)
            except Exception as e:
                logger.warning(f"Erreur broadcast vers {session.username}: {e}")

    def _broadcast_members(self):
        """Notifie tous les clients de la liste mise à jour des membres."""
        with self.clients_lock:
            members = list(self.clients.keys())
        self._broadcast({"type": "MEMBERS_UPDATE", "payload": members})

    # ── Authentification client ───────────────────────────────────────────────

    def _authenticate(self, conn: ssl.SSLSocket) -> ClientSession | None:
        """
        Handshake d'authentification :
        1. Reçoit AUTH_REQ (username, password, csr_pem)
        2. Vérifie via LDAP
        3. Signe le CSR → renvoie le certificat
        4. Envoie la clé AES de groupe chiffrée en RSA
        """
        msg = self._recv(conn)
        if not msg or msg.get("type") != SecureProtocol.TYPE_AUTH:
            conn.close()
            return None

        username    = msg.get("sender", "").strip()
        raw_payload = msg.get("payload", "{}")

        try:
            if isinstance(raw_payload, str):
                try:
                    payload = json.loads(base64.b64decode(raw_payload).decode())
                except Exception:
                    payload = json.loads(raw_payload)
            else:
                payload = raw_payload
        except Exception:
            payload = {}

        password = payload.get("password", "")
        csr_pem  = payload.get("csr_pem", "").encode()

        # Vérification LDAP
        auth = authenticate_user(username, password)
        if not auth["success"]:
            temp = ClientSession(username, conn, b"", b"")
            self._send(temp, {"type": "AUTH_FAIL", "payload": auth["error"]})
            logger.warning(f"Auth échouée — {username} : {auth['error']}")
            return None

        logger.info(f"LDAP OK — {username}")

        # Signature du CSR
        cert_pem = b""
        if csr_pem:
            try:
                cert_pem = self.ca.sign_client_csr(csr_pem)
            except Exception as e:
                logger.error(f"Erreur signature CSR pour {username}: {e}")

        # Extraction de la clé publique depuis le CSR
        public_key_pem = b""
        if csr_pem:
            try:
                csr_obj        = x509.load_pem_x509_csr(csr_pem)
                public_key_pem = csr_obj.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                )
            except Exception as e:
                logger.warning(f"Erreur extraction clé publique CSR: {e}")

        session = ClientSession(username, conn, public_key_pem, cert_pem)

        with self.clients_lock:
            self.clients[username] = session

        # Réponse AUTH_OK
        self._send(session, {
            "type":    "AUTH_OK",
            "payload": {
                "cert_pem":    cert_pem.decode() if cert_pem else "",
                "displayname": auth.get("displayname", username)
            }
        })

        # Envoi de la clé AES chiffrée en RSA
        if public_key_pem:
            self._send_group_key(session)

        # Notifier tous les membres (y compris le nouveau) de la liste à jour
        self._broadcast_members()

        logger.info(f"{username} connecté — {len(self.clients)} membre(s)")
        return session

    # ── Thread client ─────────────────────────────────────────────────────────

    def _handle_client(self, conn: ssl.SSLSocket, addr):
        """Thread dédié à chaque client connecté."""
        session = None
        try:
            logger.info(f"Connexion entrante : {addr}")
            session = self._authenticate(conn)
            if not session:
                return

            while not self.stop_event.is_set():
                msg = self._recv(conn)
                if not msg:
                    break

                if msg.get("type") == SecureProtocol.TYPE_CHAT:
                    sig_b64  = msg.get("signature")
                    payload  = msg.get("payload", "")

                    # Vérifier la signature RSA
                    if sig_b64 and session.public_key_pem:
                        try:
                            signature = base64.b64decode(sig_b64)
                            if not CryptoEngine.verify_signature(
                                session.public_key_pem, payload, signature
                            ):
                                logger.warning(f"Signature invalide de {session.username}")
                                continue
                        except Exception:
                            logger.warning(f"Erreur vérification signature de {session.username}")
                            continue

                    # Vérifier que l'expéditeur est toujours dans LDAP
                    try:
                        ldap_usernames = {u["username"] for u in list_users()}
                        if session.username not in ldap_usernames:
                            logger.warning(f"{session.username} exclu du LDAP")
                            break
                    except Exception:
                        pass

                    # Broadcast (contenu AES chiffré — jamais déchiffré par le serveur)
                    self._broadcast(msg, exclude=session.username)
                    logger.info(f"Message de {session.username} diffusé")

        except Exception as e:
            logger.error(f"Erreur client {getattr(session, 'username', str(addr))}: {e}")
        finally:
            if session:
                with self.clients_lock:
                    self.clients.pop(session.username, None)
                self._broadcast_members()
                logger.info(f"{session.username} déconnecté — {len(self.clients)} membre(s)")
            try:
                conn.close()
            except Exception:
                pass

    # ── Threads de surveillance ───────────────────────────────────────────────

    def _ldap_watcher(self):
        """Vérifie toutes les 30s si des membres ont été exclus du LDAP."""
        logger.info("Surveillance LDAP démarrée")
        while not self.stop_event.is_set():
            time.sleep(LDAP_CHECK_SECONDS)
            try:
                ldap_members = {u["username"] for u in list_users()}
                with self.clients_lock:
                    connected = set(self.clients.keys())

                excluded = connected - ldap_members
                if excluded:
                    logger.warning(f"Exclusion LDAP détectée : {excluded}")
                    for uname in excluded:
                        with self.clients_lock:
                            s = self.clients.get(uname)
                        if s:
                            try:
                                s.conn.close()
                            except Exception:
                                pass
                    self._rotate_group_key(
                        reason=f"exclusion LDAP — {', '.join(excluded)}"
                    )
            except Exception as e:
                logger.error(f"Erreur surveillance LDAP : {e}")

    def _key_scheduler(self):
        """Déclenche la rotation de clé toutes les 24h."""
        logger.info("Planificateur de rotation démarré")
        while not self.stop_event.is_set():
            time.sleep(KEY_ROTATION_HOURS * 3600)
            if not self.stop_event.is_set():
                self._rotate_group_key(reason="rotation automatique 24h")

    # ── Point d'entrée ────────────────────────────────────────────────────────

    def start(self):
        """Lance le serveur et accepte les connexions entrantes."""
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind((SERVER_HOST, SERVER_PORT))
        raw_sock.listen(10)

        secure_sock = self.tls_ctx.wrap_socket(raw_sock, server_side=True)
        logger.info(f"Serveur TLS 1.3 en écoute sur {SERVER_HOST}:{SERVER_PORT}")

        threading.Thread(target=self._ldap_watcher, daemon=True, name="ldap-watcher").start()
        threading.Thread(target=self._key_scheduler, daemon=True, name="key-scheduler").start()

        try:
            while not self.stop_event.is_set():
                try:
                    conn, addr = secure_sock.accept()
                    threading.Thread(
                        target=self._handle_client,
                        args=(conn, addr),
                        daemon=True,
                        name=f"client-{addr[0]}"
                    ).start()
                except ssl.SSLError as e:
                    logger.warning(f"Erreur TLS à l'acceptation : {e}")
                except Exception as e:
                    if not self.stop_event.is_set():
                        logger.error(f"Erreur accept : {e}")

        except KeyboardInterrupt:
            logger.info("Arrêt demandé (Ctrl+C)")
        finally:
            self.stop_event.set()
            with self.key_lock:
                CryptoEngine.secure_wipe(self.group_key)
            secure_sock.close()
            logger.info("Serveur arrêté — clé AES zéroïsée")


if __name__ == "__main__":
    server = SecureChatServer()
    server.start()
