import customtkinter as ctk


class LoginFrame(ctk.CTkFrame):
    def __init__(self, master, on_login_callback):
        super().__init__(master, fg_color="transparent")
        self.on_login_callback = on_login_callback
        self._build_ui()

    def _build_ui(self):
        # Central wrapper — placed at the geometric center of the frame
        wrapper = ctk.CTkFrame(self, fg_color="transparent")
        wrapper.place(relx=0.5, rely=0.5, anchor="center")

        # ── Card ──────────────────────────────────────────────────────────────
        card = ctk.CTkFrame(wrapper, corner_radius=20, border_width=1,
                            border_color=("gray80", "gray20"))
        card.pack(pady=(0, 16))
        card.grid_columnconfigure(0, weight=1)

        # ── Logo section ──────────────────────────────────────────────────────
        logo_area = ctk.CTkFrame(card, fg_color="transparent")
        logo_area.grid(row=0, column=0, pady=(44, 6), padx=48, sticky="ew")
        logo_area.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            logo_area, text="🔒",
            font=ctk.CTkFont(size=56)
        ).grid(row=0, column=0, pady=(0, 6))

        ctk.CTkLabel(
            logo_area, text="ChatSec",
            font=ctk.CTkFont(size=28, weight="bold")
        ).grid(row=1, column=0)

        ctk.CTkLabel(
            logo_area,
            text="Messagerie Sécurisée d'Entreprise",
            font=ctk.CTkFont(size=13),
            text_color=("gray45", "gray60")
        ).grid(row=2, column=0, pady=(5, 0))

        # ── Divider ───────────────────────────────────────────────────────────
        ctk.CTkFrame(card, height=1,
                     fg_color=("gray78", "gray22")).grid(
            row=1, column=0, sticky="ew", padx=32, pady=16
        )

        # ── Form ──────────────────────────────────────────────────────────────
        form = ctk.CTkFrame(card, fg_color="transparent")
        form.grid(row=2, column=0, padx=48, pady=0, sticky="ew")
        form.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            form, text="Identifiant LDAP",
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="w"
        ).grid(row=0, column=0, sticky="w", pady=(0, 5))

        self.username_entry = ctk.CTkEntry(
            form,
            placeholder_text="ex : j.dupont",
            height=44, corner_radius=10,
            border_width=1, border_color=("gray70", "gray30"),
            font=ctk.CTkFont(size=14)
        )
        self.username_entry.grid(row=1, column=0, sticky="ew", pady=(0, 18))

        ctk.CTkLabel(
            form, text="Mot de passe",
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="w"
        ).grid(row=2, column=0, sticky="w", pady=(0, 5))

        self.password_entry = ctk.CTkEntry(
            form,
            placeholder_text="••••••••",
            show="•", height=44, corner_radius=10,
            border_width=1, border_color=("gray70", "gray30"),
            font=ctk.CTkFont(size=14)
        )
        self.password_entry.grid(row=3, column=0, sticky="ew", pady=(0, 8))

        # Error label (hidden when empty)
        self.error_lbl = ctk.CTkLabel(
            form, text="",
            text_color="#e74c3c",
            font=ctk.CTkFont(size=12),
            wraplength=340
        )
        self.error_lbl.grid(row=4, column=0, pady=(4, 0))

        # Login button
        self.login_btn = ctk.CTkButton(
            form,
            text="Se connecter",
            height=48, corner_radius=10,
            font=ctk.CTkFont(size=15, weight="bold"),
            fg_color="#128C7E", hover_color="#0d7268",
            command=self._on_login
        )
        self.login_btn.grid(row=5, column=0, sticky="ew", pady=(20, 0))

        # Progress bar (indeterminate spinner, hidden initially)
        self.progress = ctk.CTkProgressBar(
            form, mode="indeterminate", height=4,
            progress_color="#128C7E"
        )
        self.progress.grid(row=6, column=0, sticky="ew", pady=(10, 0))
        self.progress.grid_remove()

        # ── Footer ────────────────────────────────────────────────────────────
        footer = ctk.CTkFrame(card, fg_color="transparent")
        footer.grid(row=3, column=0, pady=(18, 36), padx=48, sticky="ew")
        footer.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            footer,
            text="🛡  TLS 1.3  ·  AES-256 GCM  ·  PKI Certificate",
            font=ctk.CTkFont(size=11),
            text_color=("gray45", "gray55")
        ).grid(row=0, column=0)

        # ── Theme toggle below card ────────────────────────────────────────────
        self.theme_seg = ctk.CTkSegmentedButton(
            wrapper,
            values=["Dark", "Light"],
            command=lambda m: ctk.set_appearance_mode(m),
            width=180, height=34,
            font=ctk.CTkFont(size=12)
        )
        self.theme_seg.set("Dark")
        self.theme_seg.pack()

        # Key bindings
        self.username_entry.bind("<Return>", lambda e: self.password_entry.focus())
        self.password_entry.bind("<Return>", lambda e: self._on_login())

    # ── Public helpers (called by main_client on auth result) ─────────────────

    def show_error(self, message: str):
        self.error_lbl.configure(text=f"⚠  {message}")
        self._set_loading(False)

    def _set_loading(self, active: bool):
        if active:
            self.login_btn.configure(state="disabled", text="Connexion…")
            self.progress.grid()
            self.progress.start()
        else:
            self.login_btn.configure(state="normal", text="Se connecter")
            self.progress.stop()
            self.progress.grid_remove()

    def _on_login(self):
        user = self.username_entry.get().strip()
        pwd  = self.password_entry.get()
        self.error_lbl.configure(text="")

        if not user:
            self.show_error("Veuillez entrer votre identifiant.")
            return
        if not pwd:
            self.show_error("Veuillez entrer votre mot de passe.")
            return

        self._set_loading(True)
        from common.config import SERVER_HOST, SERVER_PORT
        self.on_login_callback(SERVER_HOST, SERVER_PORT, user, pwd)
