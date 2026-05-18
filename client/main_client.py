import sys
import os
import socket 
import ssl     
import threading
import queue
import time
import json
import struct
import base64
from tkinter import messagebox

# Alignement des chemins d'importation du projet
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import customtkinter as ctk
from ui.login_frame import LoginFrame
from ui.chat_frame import ChatFrame
from common.crypto import CryptoEngine 

# Intégration du travail de Lauraine (Phase 3.1)
try:
    from client.session_pki import generer_cle_privee, creer_csr
except ImportError:
    # Fallback de secours si le fichier est nommé différemment ou placé dans un sous-dossier
    print("[ATTENTION] Import direct de session_pki échoué. Tentative d'import alternatif...")
    try:
        from session_pki import generer_cle_privee, creer_csr
    except ImportError:
        print("[ERREUR CRITIQUE] Impossible de trouver le module session_pki de Lauraine.")

class SecureChatApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("ChatSec — Messagerie Sécurisée")
        self.resizable(True, True)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # --- ARCHITECTURE RÉSEAU ET THREADING ---
        self.secure_socket = None
        self.network_queue = queue.Queue()
        self.is_running = True
        self.is_connected = False
        
        # Stockage temporaire des identifiants et clés de session pour la reconnexion automatique
        self.current_user = None
        self.current_pwd = None
        self.client_private_key = None  # Conservée pour la signature/chiffrement après enrôlement

        # Initialisation de l'affichage
        self._show_login()
        
        # Lancement de la surveillance de la Queue par la GUI (Thread Principal)
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
        """ Gère l'événement du clic sur le bouton Connexion de l'UI. """
        self.current_user = user
        self.current_pwd = password
        
        print(f"[ChatSec] Tentative d'initialisation TLS 1.3 pour : {user}")
        
        # 1. Établissement du tunnel TLS 1.3
        if self._establish_tls_connection():
            # 2. Construction et envoi de AUTH_REQ au format strict attendu par le serveur
            if self._send_auth_request(user, password):
                # Connexion et envoi réussis -> Bascule sur l'interface principale de Chat
                self.login_frame.pack_forget()
                self._center(1120, 730)
                self.minsize(880, 600)

                self.chat_frame = ChatFrame(self, user)
                self.chat_frame.pack(expand=True, fill="both")
            else:
                print("[ERREUR] Impossible d'envoyer la demande d'authentification formalisée.")
        else:
            return

    def _establish_tls_connection(self) -> bool:
        """ Initialisation du contexte TLS, configuration du TCP Keep-Alive et emballage socket. """
        host = "127.0.0.1"
        port = 5000

        try:
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            tls_context.minimum_version = ssl.TLSVersion.TLSv1_3
            
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            ca_cert_path = os.path.join(base_dir, "server", "certs", "ca_cert.pem")
            
            tls_context.load_verify_locations(cafile=ca_cert_path)
            tls_context.verify_mode = ssl.CERT_REQUIRED
            tls_context.check_hostname = False 
        except Exception as e:
            print(f"[ERREUR CRITIQUE] Impossible de charger la configuration TLS/CA : {e}")
            messagebox.showerror("Erreur Sécurité", f"Composants de chiffrement ou certificat racine manquants :\n{e}")
            return False

        try:
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            
            self.secure_socket = tls_context.wrap_socket(raw_socket, server_hostname="chatsec.local")
            self.secure_socket.connect((host, port))
            print("[+] Tunnel TLS 1.3 établi avec succès. Certificat serveur validé via Root CA.")
            self.is_connected = True
            
            # Lancement du Thread d'écoute en arrière-plan pour la réception asynchrone framée
            threading.Thread(target=self._receive_background_loop, daemon=True).start()
            return True

        except ssl.SSLCertVerificationError as e:
            print(f"[ALERTE SÉCURITÉ] Le certificat du serveur est invalide ! {e}")
            messagebox.showerror("Alerte Sécurité", "Connexion interrompue : Le certificat du serveur est invalide.")
            return False
        except Exception as e:
            print(f"[ERREUR] Échec de la connexion réseau : {e}")
            messagebox.showerror("Erreur de connexion", f"Impossible de joindre le serveur distant.\n{e}")
            return False

    def _recv_exact(self, n: int) -> bytes:
        """ CORRECTION CRITIQUE 1 : Lit exactement n octets sur le flux TCP chiffré """
        buf = b""
        while len(buf) < n:
            chunk = self.secure_socket.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("[RESEAU] Connexion fermée par le serveur distant pendant la lecture brute.")
            buf += chunk
        return buf

    def _send_auth_request(self, user: str, password: str) -> bool:
        """ 
        CORRECTION CRITIQUE 2 & 3 : Génération du CSR via session_pki (Lauraine),
        formatage strict du dictionnaire (sender), encodage JSON interne en Base64 et framing de taille.
        """
        try:
            print("[PKI] Génération de la paire de clés éphémères et du CSR client...")
            # 1. Utilisation des fonctions de Lauraine (Phase 3.1)
            self.client_private_key = generer_cle_privee()
            csr_pem = creer_csr(user, self.client_private_key)
            
            # 2. Construction du payload interne au format attendu par le serveur
            inner_payload = json.dumps({
                "password": password,
                "csr_pem": csr_pem.decode('utf-8')
            })
            
            # 3. Construction du message enveloppe final
            auth_payload = {
                "type": "AUTH_REQ",
                "sender": user,
                "payload": base64.b64encode(inner_payload.encode('utf-8')).decode('utf-8')
            }
            
            # 4. Sérialisation et envoi framé (4 octets Big-Endian)
            serialized_data = json.dumps(auth_payload).encode('utf-8')
            self.send_data(serialized_data)
            
            print(f"[RESEAU] Enveloppe AUTH_REQ sérialisée et transmise pour '{user}'.")
            return True
        except Exception as e:
            print(f"[ERREUR] Échec de la cinématique de génération ou d'envoi AUTH_REQ : {e}")
            return False

    def _receive_background_loop(self):
        """ CORRECTION CRITIQUE 1 : Thread de réception réaligné sur le Framing TCP (Header 4 octets) """
        print("[RÉSEAU] Thread d'écoute actif (Framing TCP activé)...")
        while self.is_running and self.is_connected:
            try:
                # 1. Lire d'abord l'en-tête de 4 octets (Taille du message à venir)
                header = self._recv_exact(4)
                length = struct.unpack(">I", header)[0]
                
                # 2. Lire exactement le nombre d'octets annoncé par le header
                data = self._recv_exact(length)
                
                # 3. Transfert des octets complets vers la Queue
                self.network_queue.put(data)
                
            except Exception as e:
                print(f"[RÉSEAU] Erreur ou rupture du flux de lecture découpé : {e}")
                self.is_connected = False
                break
        
        if self.is_running:
            self._handle_disconnection_and_retry()

    def _check_queue_loop(self):
        """ Queue Réseau -> GUI : Traite les messages réseau complets désérialisés """
        try:
            while True:
                data = self.network_queue.get_nowait()
                
                # Interprétation du message JSON complet débarrassé de sa couche de framing
                try:
                    payload = json.loads(data.decode('utf-8'))
                    print(f"[GUI] Message formatté extrait de la queue : {payload}")
                    
                    # TODO Ségolène/Lauraine : Intercepter le type "AUTH_SUCCESS" ou "AUTH_FAIL" ici
                    # pour adapter graphiquement l'état ou stocker le certificat signé renvoyé.
                    
                except json.JSONDecodeError:
                    print(f"[GUI DECODAGE] Erreur : Données reçues non JSON de la queue : {data}")
                    
                self.network_queue.task_done()
        except queue.Empty:
            pass
        
        self.after(100, self._check_queue_loop)

    def _handle_disconnection_and_retry(self):
        """ Protocole robuste de reconnexion exponentielle avec ré-authentification et re-framing """
        print("[RÉSEAU] Lancement du protocole de reconnexion automatique en arrière-plan...")
        
        if hasattr(self, 'chat_frame'):
            self.chat_frame.after(0, lambda: messagebox.showwarning("Réseau", "Connexion interrompue. Tentative de reconnexion automatique..."))

        delay = 1
        max_delay = 60

        while self.is_running and not self.is_connected:
            print(f"[RÉSEAU] Prochaine tentative de reconnexion dans {delay} secondes...")
            time.sleep(delay)
            
            if self._establish_tls_connection():
                print("[RÉSEAU] Tunnel TLS 1.3 ré-établi avec succès !")
                # Ré-authentification automatique auprès du serveur avec régénération de clé/CSR
                if self.current_user and self.current_pwd:
                    self._send_auth_request(self.current_user, self.current_pwd)
                
                if hasattr(self, 'chat_frame'):
                    self.chat_frame.after(0, lambda: messagebox.showinfo("Réseau", "Connexion rétablie et session restaurée !"))
                break
            
            delay = min(delay * 2, max_delay)

    def send_data(self, data: bytes):
        """ CORRECTION CRITIQUE 1 : Injecte dynamiquement le préfixe de taille 4 octets big-endian """
        if self.secure_socket and self.is_connected:
            try:
                # 1. Calcul de la taille et empaquetage en binaire 4 octets Big-Endian (format '>I')
                header = struct.pack(">I", len(data))
                # 2. Concaténation de l'entête et des données brutes
                frame = header + data
                # 3. Envoi atomique sur le réseau
                self.secure_socket.sendall(frame)
            except Exception as e:
                print(f"[ERREUR ENVOI FRAMÉ] Échec de la transmission : {e}")
                self.is_connected = False


if __name__ == "__main__":
    app = SecureChatApp()
    app.mainloop()
    