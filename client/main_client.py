import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import customtkinter as ctk
from ui.login_frame import LoginFrame


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

        self.login_frame = LoginFrame(self, self.handle_login)
        self.login_frame.pack(expand=True, fill="both")

    def handle_login(self, server: str, user: str, password: str):
        print(f"[ChatSec] Connexion : {user}  →  {server}")

        self.login_frame.pack_forget()

        self._center(1120, 730)
        self.minsize(880, 600)

        from ui.chat_frame import ChatFrame
        self.chat_frame = ChatFrame(self, user)
        self.chat_frame.pack(expand=True, fill="both")


if __name__ == "__main__":
    app = SecureChatApp()
    app.mainloop()
