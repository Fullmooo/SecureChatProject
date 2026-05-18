import sys
import os
import socket 
import ssl     
import threading
import queue
import time
import json
from tkinter import messagebox

# Alignement des chemins d'importation du projet
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import customtkinter as ctk
from ui.login_frame import LoginFrame
from ui.chat_frame import ChatFrame
from common.crypto import CryptoEngine 

class SecureChatApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("ChatSec — Messagerie Sécurisée")
        self.resizable(True, True)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # --- ARCHITECTURE RÉSEAU ET THREADING (Phase 3.2 Complète) ---
        self.secure_socket = None
        self.network_queue = queue.Queue()
        self.is_running = True
        self.is_connected = False
        
        # Stockage temporaire des identifiants pour la reconnexion automatique
        self.current_user = None
        self.current_pwd = None

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
        
        # 1. Établissement du tunnel TLS
        if self._establish_tls_connection():
            # 2. ENVOI DE AUTH_REQ : Envoi immédiat des identifiants dès que le tunnel est actif
            if self._send_auth_request(user, password):
                # Connexion et envoi réussis -> Bascule sur l'interface principale de Chat
                self.login_frame.pack_forget()
                self._center(1120, 730)
                self.minsize(880, 600)

                self.chat_frame = ChatFrame(self, user)
                self.chat_frame.pack(expand=True, fill="both")
            else:
                print("[ERREUR] Impossible d'envoyer la demande d'authentification.")
        else:
            # L'échec de la connexion TLS est déjà géré par une boîte de dialogue
            return

    def _establish_tls_connection(self) -> bool:
        """
        Phase 3.2 : Initialisation robuste et locale du contexte TLS, 
        configuration du TCP Keep-Alive et emballage de la socket.
        """
        host = "127.0.0.1"
        port = 5000

        # CORRECTION : Le contexte TLS est initialisé ICI pour éviter les crashs d'import globaux
        try:
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            tls_context.minimum_version = ssl.TLSVersion.TLSv1_3
            
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            ca_cert_path = os.path.join(base_dir, "server", "certs", "ca_cert.pem")
            
            tls_context.load_verify_locations(cafile=ca_cert_path)
            tls_context.verify_mode = ssl.CERT_REQUIRED
            tls_context.check_hostname = False # Adapté pour l'alignement avec le serveur local de Ségolène
        except Exception as e:
            print(f"[ERREUR CRITIQUE] Impossible de charger la configuration TLS/CA : {e}")
            messagebox.showerror("Erreur Sécurité", f"Composants de chiffrement ou certificat racine manquants :\n{e}")
            return False

        try:
            # Création de la socket TCP de base
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # CORRECTION : Activation du TCP Keep-alive demandé par le CDC
            raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            
            # Emballage sécurisé en TLS 1.3
            self.secure_socket = tls_context.wrap_socket(raw_socket, server_hostname="chatsec.local")
            
            # Connexion au serveur
            self.secure_socket.connect((host, port))
            print("[+] Tunnel TLS 1.3 établi avec succès. Certificat serveur validé via Root CA.")
            self.is_connected = True
            
            # Lancement du Thread d'écoute en arrière-plan pour la réception asynchrone
            threading.Thread(target=self._receive_background_loop, daemon=True).start()
            return True

        except ssl.SSLCertVerificationError as e:
            print(f"[ALERTE SÉCURITÉ] Le certificat du serveur est invalide ou suspect ! {e}")
            messagebox.showerror("Alerte Sécurité", "Connexion interrompue : Le certificat du serveur est invalide ou suspect !")
            return False
        except Exception as e:
            print(f"[ERREUR] Échec de la connexion réseau : {e}")
            messagebox.showerror("Erreur de connexion", f"Impossible de joindre le serveur distant.\n{e}")
            return False

    def _send_auth_request(self, user: str, password: str) -> bool:
        """ CORRECTION : Envoi du paquet AUTH_REQ attendu par le serveur après le handshake TLS. """
        auth_payload = {
            "type": "AUTH_REQ",
            "username": user,
            "password": password
        }
        try:
            # Conversion en JSON et encodage en octets
            serialized_data = json.dumps(auth_payload).encode('utf-8')
            self.send_data(serialized_data)
            print(f"[RESEAU] Paquet AUTH_REQ envoyé avec succès pour l'utilisateur '{user}'.")
            return True
        except Exception as e:
            print(f"[ERREUR] Échec de l'envoi du paquet AUTH_REQ : {e}")
            return False

    def _receive_background_loop(self):
        """ Thread de réception en arrière-plan (Flux réseau -> Queue thread-safe) """
        print("[RÉSEAU] Thread d'écoute actif lancé en arrière-plan...")
        while self.is_running and self.is_connected:
            try:
                data = self.secure_socket.recv(4096)
                if not data:
                    print("[RÉSEAU] Déconnexion propre détectée depuis le serveur.")
                    self.is_connected = False
                    break
                
                # Transfert transparent des octets reçus vers la Queue pour le thread principal GUI
                self.network_queue.put(data)
                
            except Exception as e:
                print(f"[RÉSEAU] Erreur ou coupure de la socket de lecture : {e}")
                self.is_connected = False
                break
        
        # Si déconnexion accidentelle en pleine exécution, lancement de la reconnexion automatique
        if self.is_running:
            self._handle_disconnection_and_retry()

    def _check_queue_loop(self):
        """ Queue Réseau -> GUI : Traite les messages réseau de façon sécurisée pour l'interface """
        try:
            while True:
                data = self.network_queue.get_nowait()
                
                print(f"[GUI] Données extraites de la queue : {data}")
                # TODO Coordination Lauraine/Morelle/Ségolène : Traiter le retour JSON de l'authentification 
                # ou la réception de la clé de groupe AES ici.
                
                self.network_queue.task_done()
        except queue.Empty:
            pass
        
        # Ré-exécution de la vérification toutes les 100ms par CustomTkinter
        self.after(100, self._check_queue_loop)

    def _handle_disconnection_and_retry(self):
        """ Protocole robuste de reconnexion exponentielle (1s -> 2s -> 4s -> ... -> 60s max) """
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
                # Ré-authentification automatique auprès du serveur
                if self.current_user and self.current_pwd:
                    self._send_auth_request(self.current_user, self.current_pwd)
                
                if hasattr(self, 'chat_frame'):
                    self.chat_frame.after(0, lambda: messagebox.showinfo("Réseau", "Connexion rétablie et session restaurée !"))
                break
            
            delay = min(delay * 2, max_delay)

    def send_data(self, data: bytes):
        """ Permet aux composants graphiques de pousser des octets chiffrés à travers le tunnel TLS. """
        if self.secure_socket and self.is_connected:
            try:
                self.secure_socket.sendall(data)
            except Exception as e:
                print(f"[ERREUR] Échec de l'envoi sur la socket : {e}")
                self.is_connected = False


if __name__ == "__main__":
    app = SecureChatApp()
    app.mainloop()
    