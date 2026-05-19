import customtkinter as ctk
from datetime import datetime, date, timedelta

# Avatar color palette — deterministic per username
_AVATAR_PALETTE = [
    "#128C7E", "#34B7F1", "#9B59B6", "#E74C3C",
    "#F39C12", "#1ABC9C", "#3498DB", "#E67E22",
]


def _avatar_color(name: str) -> str:
    return _AVATAR_PALETTE[hash(name) % len(_AVATAR_PALETTE)]


class ChatFrame(ctk.CTkFrame):
    def __init__(self, master, username: str):
        super().__init__(master, fg_color="transparent")
        self.username = username
        self._last_msg_date: date | None = None  # tracks date for separators
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build_sidebar()
        self._build_chat_area()

    # ══════════════════════════════════════════════════════════════════════════
    # SIDEBAR
    # ══════════════════════════════════════════════════════════════════════════

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(
            self, width=285, corner_radius=0,
            fg_color=("gray92", "#111B21")
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_rowconfigure(2, weight=1)   # member list expands
        self.sidebar.grid_columnconfigure(0, weight=1)

        # ── Header ───────────────────────────────────────────────────────────
        sb_hdr = ctk.CTkFrame(
            self.sidebar, corner_radius=0, height=64,
            fg_color=("gray83", "#1F2C34")
        )
        sb_hdr.grid(row=0, column=0, sticky="ew")
        sb_hdr.grid_propagate(False)

        ctk.CTkLabel(
            sb_hdr, text="🔒  ChatSec",
            font=ctk.CTkFont(size=19, weight="bold")
        ).place(relx=0.5, rely=0.38, anchor="center")

        ctk.CTkLabel(
            sb_hdr, text="● Connexion chiffrée",
            font=ctk.CTkFont(size=11),
            text_color="#25D366"
        ).place(relx=0.5, rely=0.72, anchor="center")

        # ── Theme toggle ─────────────────────────────────────────────────────
        theme_bar = ctk.CTkFrame(
            self.sidebar, corner_radius=0, height=46,
            fg_color=("gray83", "#1F2C34")
        )
        theme_bar.grid(row=1, column=0, sticky="ew", pady=(1, 0))
        theme_bar.grid_propagate(False)

        self.theme_seg = ctk.CTkSegmentedButton(
            theme_bar,
            values=["Dark", "Light"],
            command=lambda m: ctk.set_appearance_mode(m),
            height=30, font=ctk.CTkFont(size=12)
        )
        self.theme_seg.set("Dark")
        self.theme_seg.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.86)

        # ── Member list ───────────────────────────────────────────────────────
        members_wrap = ctk.CTkFrame(
            self.sidebar, fg_color="transparent", corner_radius=0
        )
        members_wrap.grid(row=2, column=0, sticky="nsew")
        members_wrap.grid_rowconfigure(1, weight=1)
        members_wrap.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            members_wrap,
            text="UTILISATEURS EN LIGNE",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=("gray45", "gray55"),
            anchor="w"
        ).grid(row=0, column=0, padx=20, pady=(14, 6), sticky="w")

        self.member_list_frame = ctk.CTkScrollableFrame(
            members_wrap, fg_color="transparent", corner_radius=0
        )
        self.member_list_frame.grid(row=1, column=0, sticky="nsew")

        # ── Bottom user bar ───────────────────────────────────────────────────
        sb_bottom = ctk.CTkFrame(
            self.sidebar, corner_radius=0, height=58,
            fg_color=("gray83", "#1F2C34")
        )
        sb_bottom.grid(row=3, column=0, sticky="ew")
        sb_bottom.grid_propagate(False)

        initial = self.username[:1].upper() if self.username else "?"
        ctk.CTkLabel(
            sb_bottom, text=initial,
            width=36, height=36, corner_radius=18,
            fg_color=_avatar_color(self.username),
            text_color="white",
            font=ctk.CTkFont(size=14, weight="bold")
        ).place(x=14, rely=0.5, anchor="w")

        ctk.CTkLabel(
            sb_bottom, text=self.username,
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="w"
        ).place(x=60, rely=0.36, anchor="w")

        ctk.CTkLabel(
            sb_bottom, text="● En ligne",
            font=ctk.CTkFont(size=11),
            text_color="#25D366", anchor="w"
        ).place(x=60, rely=0.66, anchor="w")

    # ══════════════════════════════════════════════════════════════════════════
    # CHAT AREA
    # ══════════════════════════════════════════════════════════════════════════

    def _build_chat_area(self):
        self.chat_panel = ctk.CTkFrame(
            self, fg_color=("gray97", "#0B141A"), corner_radius=0
        )
        self.chat_panel.grid(row=0, column=1, sticky="nsew")
        self.chat_panel.grid_rowconfigure(1, weight=1)
        self.chat_panel.grid_columnconfigure(0, weight=1)

        # ── Chat header ───────────────────────────────────────────────────────
        chat_hdr = ctk.CTkFrame(
            self.chat_panel, corner_radius=0, height=64,
            fg_color=("gray83", "#1F2C34")
        )
        chat_hdr.grid(row=0, column=0, sticky="ew")
        chat_hdr.grid_propagate(False)

        info_wrap = ctk.CTkFrame(chat_hdr, fg_color="transparent")
        info_wrap.place(x=20, rely=0.5, anchor="w")

        ctk.CTkLabel(
            info_wrap, text="Groupe Sécurisé",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w")

        self.member_count_lbl = ctk.CTkLabel(
            info_wrap, text="0 membre(s) en ligne",
            font=ctk.CTkFont(size=12),
            text_color=("gray45", "gray60")
        )
        self.member_count_lbl.pack(anchor="w")

        # PKI badge (right side of header)
        badge_frame = ctk.CTkFrame(
            chat_hdr,
            fg_color=("#E8F5E9", "#0d2e1e"),
            corner_radius=14
        )
        badge_frame.place(relx=1.0, rely=0.5, anchor="e", x=-18)

        ctk.CTkLabel(
            badge_frame, text="🔒  AES-256 · PKI",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=("#1B5E20", "#25D366")
        ).pack(padx=14, pady=7)

        # ── Messages scrollable area ───────────────────────────────────────────
        self.messages_area = ctk.CTkScrollableFrame(
            self.chat_panel, fg_color="transparent", corner_radius=0
        )
        self.messages_area.grid(row=1, column=0, sticky="nsew")

        # ── Input bar ─────────────────────────────────────────────────────────
        input_bar = ctk.CTkFrame(
            self.chat_panel, corner_radius=0, height=70,
            fg_color=("gray83", "#1F2C34")
        )
        input_bar.grid(row=2, column=0, sticky="ew")
        input_bar.grid_propagate(False)
        input_bar.grid_columnconfigure(0, weight=1)

        inner = ctk.CTkFrame(input_bar, fg_color="transparent")
        inner.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.96)
        inner.grid_columnconfigure(0, weight=1)

        self.entry = ctk.CTkEntry(
            inner,
            placeholder_text="Écrire un message…",
            height=44, corner_radius=22, border_width=0,
            fg_color=("white", "#2A3942"),
            text_color=("black", "white"),
            font=ctk.CTkFont(size=14)
        )
        self.entry.grid(row=0, column=0, padx=(0, 10), sticky="ew")
        self.entry.bind("<Return>", lambda e: self.send_message())

        self.send_btn = ctk.CTkButton(
            inner, text="➤",
            width=44, height=44, corner_radius=22,
            font=ctk.CTkFont(size=16),
            fg_color="#128C7E", hover_color="#0d7268",
            text_color="white",
            command=self.send_message
        )
        self.send_btn.grid(row=0, column=1)

    # ══════════════════════════════════════════════════════════════════════════
    # PUBLIC API
    # ══════════════════════════════════════════════════════════════════════════

    _DAYS_FR   = ["Lundi","Mardi","Mercredi","Jeudi","Vendredi","Samedi","Dimanche"]
    _MONTHS_FR = ["janvier","février","mars","avril","mai","juin",
                  "juillet","août","septembre","octobre","novembre","décembre"]

    def _add_date_separator(self, d: date):
        today = date.today()
        if d == today:
            label = "Aujourd'hui"
        elif d == today - timedelta(days=1):
            label = "Hier"
        else:
            label = f"{self._DAYS_FR[d.weekday()]} {d.day} {self._MONTHS_FR[d.month - 1]} {d.year}"

        sep = ctk.CTkFrame(self.messages_area, fg_color="transparent")
        sep.pack(fill="x", pady=(10, 2))

        ctk.CTkLabel(
            sep, text=label,
            font=ctk.CTkFont(size=11),
            fg_color=("gray78", "#1F2C34"),
            text_color=("gray20", "gray75"),
            corner_radius=10
        ).pack(padx=12, pady=4)

    def add_message(self, sender: str, message: str, is_me: bool = False,
                    stored_ts: str = None):
        # Résolution de la date et de l'heure : timestamp DB (historique) ou heure courante (live)
        if stored_ts:
            try:
                _dt = datetime.fromisoformat(stored_ts)
                if _dt.tzinfo is not None:
                    _dt = _dt.astimezone()       # UTC → heure locale
                msg_date  = _dt.date()
                _time_str = _dt.strftime("%H:%M")
            except Exception:
                msg_date  = date.today()
                _time_str = datetime.now().strftime("%H:%M")
        else:
            msg_date  = date.today()
            _time_str = datetime.now().strftime("%H:%M")

        if msg_date != self._last_msg_date:
            self._last_msg_date = msg_date
            self._add_date_separator(msg_date)

        if is_me:
            bubble_color = ("#D9FDD3", "#005C4B")
            text_color   = ("black", "#E9EDE9")
            time_color   = ("#3d8c70", "#8aa49e")
        else:
            bubble_color = ("white", "#1F2C34")
            text_color   = ("black", "#E9EDE9")
            time_color   = ("gray45", "gray55")

        # Row: one message per line, aligned left or right
        row = ctk.CTkFrame(self.messages_area, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=4)

        group = ctk.CTkFrame(row, fg_color="transparent")
        group.pack(side="right" if is_me else "left", anchor="n")

        # Sender label (only for others)
        if not is_me:
            ctk.CTkLabel(
                group, text=sender,
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=(_avatar_color(sender), _avatar_color(sender)),
                anchor="w"
            ).pack(anchor="w", padx=14, pady=(2, 1))

        # Bubble
        bubble = ctk.CTkFrame(group, fg_color=bubble_color, corner_radius=16)
        bubble.pack(anchor="e" if is_me else "w", padx=2)

        ctk.CTkLabel(
            bubble, text=message,
            wraplength=400, justify="left",
            text_color=text_color,
            font=ctk.CTkFont(size=14)
        ).pack(padx=14, pady=(10, 4), anchor="w")

        # Timestamp row inside bubble
        ts_row = ctk.CTkFrame(bubble, fg_color="transparent")
        ts_row.pack(fill="x", padx=12, pady=(0, 8))

        ts = _time_str
        if is_me:
            ctk.CTkLabel(
                ts_row, text=f"✓✓  {ts}",
                font=ctk.CTkFont(size=10),
                text_color=("#25D366", "#25D366")
            ).pack(side="right")
        else:
            ctk.CTkLabel(
                ts_row, text=ts,
                font=ctk.CTkFont(size=10),
                text_color=time_color
            ).pack(side="left")

        # Auto-scroll to bottom
        self.after(60, lambda: self.messages_area._parent_canvas.yview_moveto(1.0))

    def update_member_list(self, members: list):
        for w in self.member_list_frame.winfo_children():
            w.destroy()

        for member in members:
            card = ctk.CTkFrame(
                self.member_list_frame,
                corner_radius=8,
                fg_color=("gray85", "#182229"),
                height=54
            )
            card.pack(fill="x", padx=8, pady=3)
            card.pack_propagate(False)

            # Avatar circle
            ctk.CTkLabel(
                card,
                text=member[:1].upper(),
                width=38, height=38, corner_radius=19,
                fg_color=_avatar_color(member),
                text_color="white",
                font=ctk.CTkFont(size=15, weight="bold")
            ).place(x=9, rely=0.5, anchor="w")

            info = ctk.CTkFrame(card, fg_color="transparent")
            info.place(x=57, rely=0.5, anchor="w")

            display = f"{member}  (vous)" if member == self.username else member
            ctk.CTkLabel(
                info, text=display,
                font=ctk.CTkFont(size=13, weight="bold"),
                anchor="w"
            ).pack(anchor="w")

            ctk.CTkLabel(
                info, text="● En ligne",
                font=ctk.CTkFont(size=11),
                text_color="#25D366", anchor="w"
            ).pack(anchor="w")

        if hasattr(self, "member_count_lbl"):
            n = len(members)
            self.member_count_lbl.configure(
                text=f"{n} membre{'s' if n > 1 else ''} en ligne"
            )

    def send_message(self):
        txt = self.entry.get().strip()
        if txt:
            self.add_message(self.username, txt, is_me=True)
            self.entry.delete(0, "end")
            self.master.send_chat_message(txt)
