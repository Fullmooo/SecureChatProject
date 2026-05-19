import sys
import os

# --- CORRECTION ABSOLUE DES CHEMINS (Placé obligatoirement AVANT tout import local) ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import socket
import ssl
import threading
import queue
import time
import json
import struct
import base64
from tkinter import messagebox

import customtkinter as ctk
from cryptography.hazmat.primitives import serialization
from ui.login_frame import LoginFrame
from ui.chat_frame import ChatFrame
from common.crypto import CryptoEngine

# --- INTÉGRATION PKI LAURAINE (Phase 3.1) ---
try:
    from client.session_pki import (
        generer_cle_privee, creer_csr, charger_credentials, sauvegarder_certificat
    )
except ImportError:
    try:
        from session_pki import (
            generer_cle_privee, creer_csr, charger_credentials, sauvegarder_certificat
        )
    except ImportError:
        print("[ATTENTION] Impossible d'importer session_pki. Mode dégradé sans persistance.")
        charger_credentials = None
        sauvegarder_certificat = None

# --- INTÉGRATION STOCKAGE MORELLE (Phase 3.3) ---
try:
    import client.db_manager as _db_mod
    from client.db_manager import (
        init_db, save_message, load_history, save_contact,
        wipe_key as db_wipe_key
    )
except ImportError:
    try:
        import db_manager as _db_mod
        from db_manager import (
            init_db, save_message, load_history, save_contact,
            wipe_key as db_wipe_key
        )
    except ImportError:
        print("[ATTENTION] Impossible d'importer db_manager. Pas de persistance SQLite.")
        _db_mod = None
        init_db = save_message = load_history = save_contact = db_wipe_key = None


class SecureChatApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("ChatSec — Messagerie Sécurisée")
        self.resizable(True, True)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # --- ARCHITECTURE RÉSEAU ET THREADING (Phase 3.2) ---
        self.secure_socket = None
        self.network_queue = queue.Queue()
        self.is_running = True
        self.is_connected = False

        # Stockage des identifiants et clés pour la session et la reconnexion
        self.current_user = None
        self.current_pwd = None
        self.server_host = "127.0.0.1"     # Mis à jour depuis common.config via l'UI de login
        self.server_port = 5000             # Mis à jour depuis common.config via l'UI de login
        self.client_private_key = None      # Objet clé RSA (bibliothèque cryptography)
        self.client_private_key_pem = None  # Même clé sérialisée PEM (pour CryptoEngine PyCryptodome)
        self.group_key = None               # bytearray AES-256 reçu du serveur via KEY_ROTATION
        self.is_authenticated = False       # True uniquement après AUTH_OK — bloque la reconnexion auto si auth échoue

        # Initialisation de la GUI
        self._show_login()

        # Fermeture propre : zeroise les clés sensibles en RAM
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Lancement de la surveillance de la Queue réseau par le thread principal GUI
        self._check_queue_loop()

    def _center(self, w: int, h: int):
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x  = (sw - w) // 2
        y  = (sh - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _show_login(self):
        self._center(480, 660)
        self.minsize(420, 580)
        self.login_frame = LoginFrame(self, self.handle_login)
        self.login_frame.pack(expand=True, fill="both")

    def handle_login(self, server_from_ui: str, port_from_ui: int, user: str, password: str):
        """ Gère l'événement de connexion lors du clic sur le bouton de l'UI. """
        self.current_user = user
        self.current_pwd = password
        self.server_host = server_from_ui or "127.0.0.1"
        self.server_port = port_from_ui or 5000
        self.is_authenticated = False  # Réinitialisation à chaque tentative de connexion

        print(f"[ChatSec] Tentative d'initialisation TLS 1.3 pour l'utilisateur : {user}")

        # 1. Établissement du tunnel TLS 1.3
        if self._establish_tls_connection():
            # 2. Authentification et enrôlement PKI via AUTH_REQ complet
            if self._send_auth_request(user, password):
                self.login_frame.pack_forget()
                self._center(1120, 730)
                self.minsize(880, 600)

                self.chat_frame = ChatFrame(self, user)
                self.chat_frame.pack(expand=True, fill="both")
            else:
                print("[ERREUR] Échec de la construction ou de l'envoi du paquet AUTH_REQ.")
        else:
            return

    def _establish_tls_connection(self) -> bool:
        """ Initialisation locale du contexte TLS, configuration du TCP Keep-Alive et emballage socket. """
        host = self.server_host
        port = self.server_port

        try:
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            tls_context.minimum_version = ssl.TLSVersion.TLSv1_3

            ca_cert_path = os.path.join(BASE_DIR, "server", "certs", "ca_cert.pem")
            tls_context.load_verify_locations(cafile=ca_cert_path)
            tls_context.verify_mode = ssl.CERT_REQUIRED
            tls_context.check_hostname = False
        except Exception as e:
            print(f"[ERREUR SÉCURITÉ] Impossible de charger le certificat racine CA : {e}")
            messagebox.showerror("Erreur Sécurité", f"Certificat d'autorité (ca_cert.pem) introuvable ou invalide :\n{e}")
            return False

        try:
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Options du CDC : Activation du TCP Keep-Alive
            raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

            # Connexion et emballage sécurisé
            self.secure_socket = tls_context.wrap_socket(raw_socket, server_hostname="chatsec.local")
            self.secure_socket.connect((host, port))
            print("[+] Tunnel TLS 1.3 établi. Certificat serveur validé par la CA.")
            self.is_connected = True

            # Lancement du thread d'écoute réseau en arrière-plan
            threading.Thread(target=self._receive_background_loop, daemon=True).start()
            return True

        except ssl.SSLCertVerificationError as e:
            print(f"[ALERTE SÉCURITÉ] Échec de la vérification du certificat serveur ! {e}")
            messagebox.showerror("Alerte Sécurité", "Le certificat du serveur est invalide ou corrompu.")
            return False
        except Exception as e:
            print(f"[ERREUR RÉSEAU] Impossible de joindre le serveur : {e}")
            messagebox.showerror("Erreur de connexion", f"Le serveur distant est injoignable.\n{e}")
            return False

    def _recv_exact(self, n: int) -> bytes:
        """ Garantie de lecture stricte : lit exactement n octets sur le flux TCP chiffré (Framing) """
        buf = b""
        while len(buf) < n:
            chunk = self.secure_socket.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Flux TCP interrompu prématurément par le serveur.")
            buf += chunk
        return buf

    def _send_auth_request(self, user: str, password: str) -> bool:
        """ Construit et envoie le paquet AUTH_REQ selon le format attendu (b64, clé persistée, framing). """
        try:
            # 1. Gestion stricte et réutilisation de la clé privée
            if self.client_private_key is not None:
                print("[PKI] Réutilisation de la clé privée déjà instanciée en mémoire.")
            elif charger_credentials is not None:
                # Appel sans argument et déstructuration propre du tuple (cle, cert)
                cle, cert = charger_credentials()
                if cle:
                    self.client_private_key = cle
                    print("[PKI] Clé privée existante rechargée avec succès via le module de Lauraine.")

            # Si aucune clé n'existe nulle part (première connexion), on la génère
            if self.client_private_key is None:
                print("[PKI] Aucune clé disponible. Génération d'un nouveau couple de clés RSA...")
                self.client_private_key = generer_cle_privee()

            # Sérialisation : objet clé (bibliothèque cryptography) → PEM bytes (pour CryptoEngine PyCryptodome)
            self.client_private_key_pem = self.client_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

            # 2. Génération du CSR à partir de la clé validée
            csr_pem = creer_csr(user, self.client_private_key)

            # 3. Formatage du payload interne
            inner_payload = json.dumps({
                "password": password,
                "csr_pem": csr_pem.decode('utf-8')
            })

            # Enveloppe globale requise par le protocole du serveur
            auth_payload = {
                "type": "AUTH_REQ",
                "sender": user,
                "payload": base64.b64encode(inner_payload.encode('utf-8')).decode('utf-8')
            }

            # 4. Sérialisation et envoi
            serialized_data = json.dumps(auth_payload).encode('utf-8')
            self.send_data(serialized_data)

            print(f"[RÉSEAU] Message AUTH_REQ empaqueté et poussé pour l'utilisateur '{user}'.")
            return True
        except Exception as e:
            print(f"[ERREUR CRYPTO/RÉSEAU] Échec de la procédure AUTH_REQ : {e}")
            return False

    def _receive_background_loop(self):
        """ Réception asynchrone permanente basée sur le Framing TCP (Header de 4 octets Big-Endian) """
        print("[RÉSEAU] Thread d'écoute en arrière-plan activé.")
        while self.is_running and self.is_connected:
            try:
                # 1. Lecture de l'en-tête de taille (4 octets)
                header = self._recv_exact(4)
                length = struct.unpack(">I", header)[0]

                # 2. Lecture exacte de la taille annoncée
                data = self._recv_exact(length)

                # 3. Transmission sécurisée à la Queue pour traitement graphique
                self.network_queue.put(data)

            except Exception as e:
                print(f"[RÉSEAU] Déconnexion ou anomalie sur le flux d'écoute : {e}")
                self.is_connected = False
                break

        if self.is_running:
            self._handle_disconnection_and_retry()

    def _check_queue_loop(self):
        """ Thread Principal (GUI) : Consomme et traite les messages réseau complets sans bloquer l'UI """
        try:
            while True:
                data = self.network_queue.get_nowait()
                try:
                    payload = json.loads(data.decode('utf-8'))
                    self._handle_server_message(payload)
                except json.JSONDecodeError:
                    print(f"[GUI] Erreur critique de parsing JSON sur la queue : {data}")
                self.network_queue.task_done()
        except queue.Empty:
            pass

        self.after(100, self._check_queue_loop)

    def _handle_server_message(self, payload: dict):
        """ Dispatche chaque message serveur vers le bon gestionnaire selon son type. """
        msg_type = payload.get("type")

        if msg_type == "AUTH_OK":
            self.is_authenticated = True
            auth_data = payload.get("payload", {})
            cert_pem_str = auth_data.get("cert_pem", "")

            # Persistance du certificat X.509 signé par la CA
            if cert_pem_str and sauvegarder_certificat:
                try:
                    sauvegarder_certificat(cert_pem_str.encode('utf-8'))
                    print("[PKI] Certificat X.509 reçu et sauvegardé localement.")
                except Exception as e:
                    print(f"[PKI] Erreur sauvegarde certificat : {e}")

            # Initialisation de la base de données chiffrée (PBKDF2 + AES-256)
            # Chemin par utilisateur pour éviter les collisions lors des tests multi-clients sur la même machine
            if init_db and self.current_pwd and self.current_user:
                try:
                    user_storage = os.path.join(BASE_DIR, "storage", self.current_user)
                    os.makedirs(user_storage, exist_ok=True)
                    if _db_mod:
                        _db_mod.DB_PATH = os.path.join(user_storage, "chat_history.db")
                    init_db(self.current_pwd, self.current_user)
                except Exception as e:
                    print(f"[DB] Erreur init_db : {e}")

            # Chargement de l'historique local dans l'UI
            if load_history and hasattr(self, 'chat_frame'):
                try:
                    for msg in load_history():
                        is_me = msg["sender"] == self.current_user
                        self.chat_frame.add_message(
                            msg["sender"], msg["content"],
                            is_me=is_me, stored_ts=msg.get("timestamp")
                        )
                except Exception as e:
                    print(f"[DB] Erreur load_history : {e}")

        elif msg_type == "AUTH_FAIL":
            error = payload.get("payload", "Authentification refusée.")
            print(f"[AUTH] Refus serveur : {error}")
            # Retour à l'écran de connexion
            if hasattr(self, 'chat_frame'):
                self.chat_frame.pack_forget()
            self._center(480, 660)
            self.minsize(420, 580)
            if hasattr(self, 'login_frame'):
                self.login_frame.pack(expand=True, fill="both")
                self.login_frame.show_error(str(error))

        elif msg_type == "KEY_ROTATION":
            encrypted_key_b64 = payload.get("payload", "")
            if encrypted_key_b64 and self.client_private_key_pem:
                try:
                    encrypted_key = base64.b64decode(encrypted_key_b64)
                    raw_key = CryptoEngine.decrypt_rsa(self.client_private_key_pem, encrypted_key)
                    if self.group_key is not None:
                        CryptoEngine.secure_wipe(self.group_key)
                    self.group_key = bytearray(raw_key)
                    print(f"[CRYPTO] Clé AES de groupe reçue et déchiffrée ({len(self.group_key)} octets).")
                except Exception as e:
                    print(f"[ERREUR CRYPTO] Impossible de déchiffrer la clé AES de groupe : {e}")

        elif msg_type == "MEMBERS_UPDATE":
            members = payload.get("payload", [])
            if hasattr(self, 'chat_frame'):
                self.chat_frame.update_member_list(members)

        elif msg_type == "CHAT_MSG":
            sender = payload.get("sender", "Inconnu")
            payload_b64 = payload.get("payload", "")
            if payload_b64 and self.group_key:
                try:
                    encrypted_bytes = base64.b64decode(payload_b64)
                    plaintext = CryptoEngine.decrypt_aes_gcm(bytearray(self.group_key), encrypted_bytes)
                    is_me = (sender == self.current_user)
                    if hasattr(self, 'chat_frame'):
                        self.chat_frame.add_message(sender, plaintext, is_me=is_me)
                    if save_message:
                        save_message(sender, plaintext)
                except Exception as e:
                    print(f"[ERREUR CRYPTO] Déchiffrement message de {sender} impossible : {e}")
        else:
            print(f"[GUI] Type de message non reconnu : {msg_type}")

    def send_chat_message(self, text: str):
        """ Chiffre (AES-256 GCM), signe (RSA-PSS) et envoie un CHAT_MSG. Sauvegarde en base locale. """
        if not self.group_key:
            print("[ERREUR] Clé AES de groupe non disponible — message non envoyé.")
            return
        if not self.client_private_key_pem:
            print("[ERREUR] Clé privée non disponible — message non envoyé.")
            return
        try:
            encrypted_bytes = CryptoEngine.encrypt_aes_gcm(bytearray(self.group_key), text)
            payload_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')

            signature = CryptoEngine.sign_message(self.client_private_key_pem, payload_b64)
            sig_b64 = base64.b64encode(signature).decode('utf-8')

            msg = {
                "type":      "CHAT_MSG",
                "sender":    self.current_user,
                "payload":   payload_b64,
                "signature": sig_b64
            }
            self.send_data(json.dumps(msg).encode('utf-8'))

            if save_message:
                save_message(self.current_user, text)

        except Exception as e:
            print(f"[ERREUR CRYPTO] Impossible de chiffrer/envoyer le message : {e}")

    def _handle_disconnection_and_retry(self):
        """ Stratégie de repli : Reconnexion exponentielle (1s -> 2s -> 4s -> ... -> 60s) avec clé stable """
        if not self.is_authenticated:
            print("[RÉSEAU] Connexion fermée après échec d'authentification — pas de reconnexion automatique.")
            return
        print("[RÉSEAU] Connexion perdue. Lancement du protocole de reconnexion automatique...")

        if hasattr(self, 'chat_frame'):
            self.chat_frame.after(0, lambda: messagebox.showwarning("Réseau", "Liaison interrompue. Tentative de reconnexion..."))

        delay = 1
        max_delay = 60

        while self.is_running and not self.is_connected:
            print(f"[RÉSEAU] Reconnexion initiée dans {delay} secondes...")
            time.sleep(delay)

            if self._establish_tls_connection():
                print("[RÉSEAU] Tunnel TLS 1.3 restauré.")
                # Ré-authentification transparente avec conservation de self.client_private_key
                if self.current_user and self.current_pwd:
                    self._send_auth_request(self.current_user, self.current_pwd)

                if hasattr(self, 'chat_frame'):
                    self.chat_frame.after(0, lambda: messagebox.showinfo("Réseau", "Connexion rétablie ! Session synchronisée."))
                break

            delay = min(delay * 2, max_delay)

    def send_data(self, data: bytes):
        """ Ajoute l'en-tête de taille 4 octets Big-Endian (Framing) et écrit sur la socket sécurisée """
        if self.secure_socket and self.is_connected:
            try:
                header = struct.pack(">I", len(data))
                frame = header + data
                self.secure_socket.sendall(frame)
            except Exception as e:
                print(f"[ERREUR TRANSMISSION] Impossible d'écrire sur le socket : {e}")
                self.is_connected = False

    def _on_close(self):
        """ Fermeture propre : zeroise les clés sensibles en RAM avant de quitter. """
        self.is_running = False
        if self.group_key is not None:
            CryptoEngine.secure_wipe(self.group_key)
            self.group_key = None
        if db_wipe_key:
            db_wipe_key()
        if self.secure_socket:
            try:
                self.secure_socket.close()
            except Exception:
                pass
        self.destroy()


if __name__ == "__main__":
    app = SecureChatApp()
    app.mainloop()
