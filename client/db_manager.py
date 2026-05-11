"""
Module 3.3 — Stockage local SQLite chiffré

Rôle : Sauvegarder et charger les messages de manière chiffrée
       dans une base SQLite locale (chat_history.db).
       Les messages sont chiffrés avec AES-256 GCM avant d'être écrits.
       La clé AES est dérivée du mot de passe LDAP via PBKDF2.
"""

import sqlite3
import os
import hashlib
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ─────────────────────────────────────────────
# CHEMIN DE LA BASE DE DONNÉES
# ─────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "storage", "chat_history.db")

# Clé AES globale (stockée en RAM uniquement, jamais sur disque)
_aes_key = None


# ─────────────────────────────────────────────
# FONCTIONS INTERNES (privées)
# ─────────────────────────────────────────────

def _derive_key(password: str, salt: bytes) -> bytearray:
    """
    Dérive une clé AES-256 depuis le mot de passe LDAP via PBKDF2.
    Le sel doit être fourni (généré aléatoirement et stocké en base).
    
    Args:
        password: mot de passe LDAP
        salt: sel aléatoire stocké (16 octets)
    
    Returns:
        Clé de 32 octets en tant que bytearray (mutable, pour pouvoir zéroïser)
    """
    key = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt,
        iterations=200_000,   # 200 000 itérations = résistant aux attaques brute force
        dklen=32              # 32 octets = AES-256
    )
    # Retourner en bytearray pour pouvoir zéroïser la mémoire plus tard
    return bytearray(key)


def _get_or_create_salt(conn: sqlite3.Connection) -> bytes:
    """
    Récupère le sel stocké de la base, ou en génère un nouveau et le stocke.
    Cela garantit un sel unique et aléatoire par base de données (= par utilisateur).
    
    Returns:
        Sel de 16 octets (stocké en base)
    """
    cursor = conn.cursor()
    
    # Chercher le sel existant
    cursor.execute("SELECT salt FROM config WHERE id = 1")
    row = cursor.fetchone()
    
    if row:
        return row[0]
    
    # Sinon, générer un nouveau sel aléatoire
    salt = get_random_bytes(16)
    cursor.execute(
        "INSERT INTO config (id, salt) VALUES (1, ?)",
        (salt,)
    )
    conn.commit()
    return salt


def _encrypt(plaintext: str) -> tuple[bytes, bytes, bytes]:
    """
    Chiffre un texte avec AES-256 GCM.
    Retourne (nonce, ciphertext, tag).
    """
    cipher = AES.new(_aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return cipher.nonce, ciphertext, tag


def _decrypt(nonce: bytes, ciphertext: bytes, tag: bytes) -> str:
    """
    Déchiffre et vérifie l'intégrité avec AES-256 GCM.
    Lève une exception si le message a été altéré.
    """
    cipher = AES.new(_aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8")


def _get_connection() -> sqlite3.Connection:
    """Ouvre et retourne une connexion à la base SQLite."""
    return sqlite3.connect(DB_PATH)


# ─────────────────────────────────────────────
# FONCTIONS PUBLIQUES (interface du module)
# ─────────────────────────────────────────────

def init_db(password: str, username: str) -> None:
    """
    À appeler une seule fois au démarrage du client.

    - Crée la base SQLite si elle n'existe pas
    - Génère un sel aléatoire unique et le stocke en base
    - Dérive la clé AES depuis le mot de passe LDAP et ce sel
    - Crée les tables messages et contacts

    Args:
        password: le mot de passe LDAP de l'utilisateur
        username: identifiant de l'utilisateur
    """
    global _aes_key

    # 1. Ouvrir/créer la base
    conn = _get_connection()
    cursor = conn.cursor()

    # 2. Créer la table de configuration (stocke le sel aléatoire)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS config (
            id   INTEGER PRIMARY KEY,
            salt BLOB NOT NULL
        )
    """)

    # Table des messages
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            sender    TEXT    NOT NULL,
            content   BLOB    NOT NULL,
            nonce     BLOB    NOT NULL,
            tag       BLOB    NOT NULL,
            timestamp TEXT    NOT NULL
        )
    """)

    # Table des contacts (cache des certificats X.509)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            username TEXT PRIMARY KEY,
            cert_pem TEXT NOT NULL
        )
    """)

    # 3. Obtenir ou créer le sel aléatoire unique
    salt = _get_or_create_salt(conn)

    # 4. Dériver la clé AES depuis le mot de passe + sel aléatoire
    _aes_key = _derive_key(password, salt)

    conn.commit()
    conn.close()
    print("[DB] Base de données initialisée.")


def save_message(sender: str, content: str, timestamp: str = None) -> None:
    """
    Chiffre et sauvegarde un message en base.
    Appelée par le thread GUI à chaque message reçu ou envoyé.

    Args:
        sender:    nom de l'expéditeur (ex: "alice")
        content:   texte du message en clair
        timestamp: horodatage ISO (optionnel, généré automatiquement si absent)
    """
    if _aes_key is None:
        raise RuntimeError("init_db() doit être appelée avant save_message()")

    if timestamp is None:
        from datetime import datetime, timezone
        timestamp = datetime.now(timezone.utc).isoformat()

    # Chiffrer le contenu avant d'écrire en base
    nonce, ciphertext, tag = _encrypt(content)

    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO messages (sender, content, nonce, tag, timestamp) VALUES (?, ?, ?, ?, ?)",
        (sender, ciphertext, nonce, tag, timestamp)
    )
    conn.commit()
    conn.close()


def load_history() -> list[dict]:
    """
    Charge et déchiffre tous les messages depuis la base.
    Appelée par l'UI au démarrage pour afficher l'historique.

    Returns:
        Liste de dicts : [{"sender": "alice", "content": "Salut", "timestamp": "..."}, ...]
        Ordonnée du plus ancien au plus récent.
    """
    if _aes_key is None:
        raise RuntimeError("init_db() doit être appelée avant load_history()")

    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT sender, content, nonce, tag, timestamp FROM messages ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()

    messages = []
    for sender, ciphertext, nonce, tag, timestamp in rows:
        try:
            content = _decrypt(bytes(nonce), bytes(ciphertext), bytes(tag))
            messages.append({
                "sender":    sender,
                "content":   content,
                "timestamp": timestamp
            })
        except Exception:
            # Message corrompu ou clé incorrecte — on l'ignore proprement
            messages.append({
                "sender":    sender,
                "content":   "[Message illisible]",
                "timestamp": timestamp
            })

    return messages


def save_contact(username: str, cert_pem: str) -> None:
    """
    Sauvegarde ou met à jour le certificat X.509 d'un contact en cache local.
    Utilisé pour vérifier les signatures sans redemander au serveur.

    Args:
        username: nom de l'utilisateur (ex: "bob")
        cert_pem: certificat X.509 au format PEM (string)
    """
    conn = _get_connection()
    cursor = conn.cursor()
    # INSERT OR REPLACE = mise à jour si le contact existe déjà
    cursor.execute(
        "INSERT OR REPLACE INTO contacts (username, cert_pem) VALUES (?, ?)",
        (username, cert_pem)
    )
    conn.commit()
    conn.close()


def get_contact(username: str) -> dict | None:
    """
    Récupère un contact depuis le cache local.

    Args:
        username: nom de l'utilisateur à chercher

    Returns:
        Dict {"username": ..., "cert_pem": ...} ou None si introuvable
    """
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, cert_pem FROM contacts WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    return {"username": row[0], "cert_pem": row[1]}


def wipe_key() -> None:
    """
    Efface complètement la clé AES de la RAM lors de la fermeture de l'application.
    Zéroïse chaque octet du bytearray (mutable) avant de libérer la référence.
    À appeler dans la routine de cleanup (Phase 4.1 / fermeture fenêtre).
    """
    global _aes_key
    if _aes_key is not None:
        # Zéroïser chaque octet individuellement (bytearray est mutable)
        for i in range(len(_aes_key)):
            _aes_key[i] = 0
        # Puis libérer la référence
        _aes_key = None
    print("[DB] Clé AES zéroïsée et effacée de la RAM.")
