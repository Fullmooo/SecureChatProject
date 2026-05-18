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
from ui.login_frame import LoginFrame
from ui.chat_frame import ChatFrame
from common.crypto import CryptoEngine 

# --- INTÉGRATION PKI LAURAINE (Phase 3.1) ---
try:
    from client.session_pki import generer_cle_privee, creer_csr, charger_credentials
except ImportError:
    try:
        from session_pki import generer_cle_privee, creer_csr, charger_credentials
    except ImportError:
        print("[ATTENTION] Impossible d'importer session_pki. Mode dégradé sans persistance.")
        charger_credentials = None

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
        self.client_private_key = None  # Stocke uniquement l'objet clé RSA

        # Initialisation de la GUI
        self._show_login()
        
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

    def handle_login(self, server_from_ui: str, user: str, password: str):
        """ Gère l'événement de connexion lors du clic sur le bouton de l'UI. """
        self.current_user = user
        self.current_pwd = password
        
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
        host = "127.0.0.1"
        port = 5000

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
                # CORRECTION : Appel sans argument et déstructuration propre du tuple (cle, cert)
                cle, cert = charger_credentials()
                if cle:
                    self.client_private_key = cle
                    print("[PKI] Clé privée existante rechargée avec succès via le module de Lauraine.")
            
            # Si aucune clé n'existe nulle part (première connexion), on la génère
            if self.client_private_key is None:
                print("[PKI] Aucune clé disponible. Génération d'un nouveau couple de clés RSA...")
                self.client_private_key = generer_cle_privee()
            
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
        """ Thread Principal (GUI) : Consomme et applique les messages complets de la Queue sans bloquer l'UI """
        try:
            while True:
                data = self.network_queue.get_nowait()
                try:
                    payload = json.loads(data.decode('utf-8'))
                    print(f"[GUI] Données prêtes extraites de la queue : {payload}")
                except json.JSONDecodeError:
                    print(f"[GUI] Erreur critique de parsing JSON sur la queue : {data}")
                self.network_queue.task_done()
        except queue.Empty:
            pass
        
        self.after(100, self._check_queue_loop)

    def _handle_disconnection_and_retry(self):
        """ Stratégie de repli : Reconnexion exponentielle (1s -> 2s -> 4s -> ... -> 60s) avec clé stable """
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


if __name__ == "__main__":
    app = SecureChatApp()
    app.mainloop()

    