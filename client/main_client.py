<<<<<<< Updated upstream
=======
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import socket 
import ssl     
from tkinter import messagebox # Pour l'affichage de l'alerte de sécurité critique
from common.crypto import CryptoEngine 

import customtkinter as ctk
from ui.login_frame import LoginFrame

# Configuration du contexte TLS 1.3 (Phase 3.2)
tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
tls_context.minimum_version = ssl.TLSVersion.TLSv1_3

# Déduction automatique du chemin absolu pour localiser le ca_cert.pem
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CA_CERT_PATH = os.path.join(BASE_DIR, "server", "certs", "ca_cert.pem")

tls_context.load_verify_locations(cafile=CA_CERT_PATH)

# ACCORD AVEC LE SERVEUR : On exige un certificat valide (Sécurité maximale)
tls_context.verify_mode = ssl.CERT_REQUIRED

# Comme Ségolène utilise le certificat Root CA directement sur le serveur,
# la vérification stricte du nom de domaine (check_hostname) va bloquer en local.
# On la passe à False pour valider l'identité par la chaîne de confiance de la CA uniquement.
tls_context.check_hostname = False

class SecureChatApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("ChatSec — Messagerie Sécurisée")
        self.resizable(True, True)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self._show_login()

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

        # La LoginFrame appelle handle_login avec (SERVER_HOST, user, pwd)
        self.login_frame = LoginFrame(self, self.handle_login)
        self.login_frame.pack(expand=True, fill="both")

    def handle_login(self, server_from_ui: str, user: str, password: str):
        # On s'aligne sur les constantes de Ségolène (0.0.0.0 sur le serveur = 127.0.0.1 en local)
        host = "127.0.0.1"
        port = 5000

        print(f"[ChatSec] Tentative de connexion TLS 1.3 : {user}  →  {host}:{port}")

        try:
            # 1. Création de la socket TCP brute
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # 2. Emballage de la socket dans le tunnel TLS 1.3 (Mission Phase 3.2)
            # Puisque check_hostname = False, la valeur de server_hostname sert d'indication 
            # mais ne fera plus planter la poignée de main.
            secure_socket = tls_context.wrap_socket(raw_socket, server_hostname="chatsec.local")
            
            # 3. Connexion effective au serveur de Ségolène
            secure_socket.connect((host, port))
            print("[+] Tunnel TLS 1.3 établi avec succès. Certificat serveur validé via Root CA.")

            # --- LES ÉTAPES SUIVANTES SERONT À COORDONNER AVEC TES CAMARADES ---
            # TODO: Envoyer les credentials (user/password) via le tunnel pour l'auth LDAP (Lauraine/Morelle)
            # TODO: Réceptionner la clé AES de groupe chiffrée et faire :
            # self.group_key = CryptoEngine.decrypt_rsa(ma_cle_privee, cle_recue)
            # ------------------------------------------------------------------

        except ssl.SSLCertVerificationError as e:
            print(f"[ALERTE SÉCURITÉ] Le certificat du serveur est invalide ou suspect ! {e}")
            messagebox.showerror(
                "Alerte Sécurité", 
                "Connexion non sécurisée :\n\nLe certificat du serveur ne correspond pas à l'autorité racine du projet !\nLa connexion a été coupée."
            )
            return

        except Exception as e:
            print(f"[ERREUR] Échec de la connexion réseau : {e}")
            messagebox.showerror("Erreur de connexion", f"Impossible de joindre le serveur :\n{e}")
            return

        # Si tout est OK, on passe à l'interface de chat
        self.login_frame.pack_forget()

        self._center(1120, 730)
        self.minsize(880, 600)

        from ui.chat_frame import ChatFrame
        self.chat_frame = ChatFrame(self, user)
        self.chat_frame.pack(expand=True, fill="both")


if __name__ == "__main__":
    app = SecureChatApp()
    app.mainloop()
    
>>>>>>> Stashed changes
