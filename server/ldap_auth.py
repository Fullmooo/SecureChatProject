"""
server/ldap_auth.py
Module 2.2 — Authentification LDAPS

Rôle : Authentifier les utilisateurs via un serveur OpenLDAP (LDAPS port 636).
       Gérer les comptes utilisateurs (ajout, suppression, liste).
       Ce module est appelé par le serveur de chat avant d'autoriser une connexion.

Dépendance : pip install ldap3
"""

import os
import ssl
import logging
import hashlib
import base64
from ldap3 import (
    Server, Connection, ALL,
    SUBTREE, MODIFY_ADD, MODIFY_REPLACE,
    Tls, SIMPLE
)
from ldap3.core.exceptions import (
    LDAPBindError,
    LDAPSocketOpenError,
    LDAPException
)

# ─────────────────────────────────────────────
# CONFIGURATION DU SERVEUR LDAP
# ─────────────────────────────────────────────

LDAP_HOST         = "127.0.0.1"
LDAP_PORT         = 636                  # 636 = LDAPS (port standard sécurisé)
LDAP_DOMAIN       = "chatsec.local"
LDAP_BASE_DN      = "dc=chatsec,dc=local"
LDAP_ADMIN_DN     = f"cn=admin,{LDAP_BASE_DN}"
LDAP_ADMIN_PASS   = "Pyproject@237"      # Correspond au Docker chatsec-ldap
LDAP_USERS_OU     = f"ou=users,{LDAP_BASE_DN}"
LDAP_GROUP_CN     = f"cn=securechat,ou=groups,{LDAP_BASE_DN}"
LDAP_CERTS_DIR    = os.path.join(os.path.dirname(__file__), "certs")
LDAP_CA_CERT_PATH = os.path.join(LDAP_CERTS_DIR, "ldap_ca_cert.pem")
LDAP_CA_CERT_FALLBACK_PATH = os.path.join(LDAP_CERTS_DIR, "ca_cert.pem")
LDAP_TLS_VALIDATE = False
USE_MOCK_LDAP     = False  # True = mock local, False = vrai serveur LDAP Docker

# Utilisateurs mock — actifs quand USE_MOCK_LDAP = True
_MOCK_USERS = {
    "segolene": {"password": "mdp_segolene", "email": "segolene@chatsec.local", "displayname": "Ségolène"},
    "joyce":    {"password": "mdp_joyce",    "email": "joyce@chatsec.local",    "displayname": "Joyce"},
    "lauraine": {"password": "mdp_lauraine", "email": "lauraine@chatsec.local", "displayname": "Lauraine"},
    "morelle":  {"password": "mdp_morelle",  "email": "morelle@chatsec.local",  "displayname": "Morelle"},
}

# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="[LDAP] %(asctime)s — %(levelname)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("ldap_auth")


# ─────────────────────────────────────────────
# FONCTIONS INTERNES
# ─────────────────────────────────────────────

def _get_ldap_tls() -> Tls:
    """Retourne un objet TLS configuré pour valider le certificat LDAP."""
    if USE_MOCK_LDAP:
        return Tls(validate=ssl.CERT_NONE)
    
    if not os.path.isdir(LDAP_CERTS_DIR):
        os.makedirs(LDAP_CERTS_DIR, exist_ok=True)

    if LDAP_TLS_VALIDATE:
        if os.path.isfile(LDAP_CA_CERT_PATH):
            ca_file = LDAP_CA_CERT_PATH
        elif os.path.isfile(LDAP_CA_CERT_FALLBACK_PATH):
            ca_file = LDAP_CA_CERT_FALLBACK_PATH
            logger.warning(
                f"Fichier CA LDAP principal introuvable, utilisation du fallback : {ca_file}"
            )
        else:
            logger.error(f"Fichier CA LDAP introuvable : {LDAP_CA_CERT_PATH}")
            raise FileNotFoundError(
                f"LDAP CA cert file not found: {LDAP_CA_CERT_PATH}"
            )
        return Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_file)
    return Tls(validate=ssl.CERT_NONE)


def _get_admin_connection() -> Connection:
    """Ouvre une connexion admin au serveur LDAP."""
    if USE_MOCK_LDAP:
        # Mock simple : retourne une connexion fictive
        class MockConnection:
            def unbind(self): pass
            def search(self, **kwargs): self.entries = []
            def modify(self, **kwargs): pass
            def add(self, **kwargs): return True
            def delete(self, **kwargs): return True
        return MockConnection()
    
    tls = _get_ldap_tls()
    server = Server(LDAP_HOST, port=LDAP_PORT, use_ssl=True, tls=tls, get_info=ALL)
    conn = Connection(
        server,
        user=LDAP_ADMIN_DN,
        password=LDAP_ADMIN_PASS,
        authentication=SIMPLE,
        auto_bind=True
    )
    return conn


def _user_exists(conn: Connection, username: str) -> bool:
    """
    Vérifie si un utilisateur existe déjà dans l'annuaire LDAP.
    Utilisée en interne avant toute création de compte.

    Args:
        conn     : connexion admin déjà ouverte
        username : identifiant à vérifier

    Returns:
        True si l'utilisateur existe, False sinon
    """
    conn.search(
        search_base=LDAP_USERS_OU,
        search_filter=f"(cn={username})",
        search_scope=SUBTREE,
        attributes=["cn"]
    )
    return len(conn.entries) > 0


def _email_exists(conn: Connection, email: str) -> bool:
    """
    Vérifie si une adresse email est déjà utilisée par un autre compte.

    Args:
        conn  : connexion admin déjà ouverte
        email : adresse email à vérifier

    Returns:
        True si l'email est déjà pris, False sinon
    """
    conn.search(
        search_base=LDAP_USERS_OU,
        search_filter=f"(mail={email})",
        search_scope=SUBTREE,
        attributes=["cn"]
    )
    return len(conn.entries) > 0


def _hash_password(password: str) -> str:
    """Hash et sale le mot de passe avant stockage LDAP."""
    salt = os.urandom(8)
    digest = hashlib.sha1(password.encode("utf-8") + salt).digest()
    return "{SSHA}" + base64.b64encode(digest + salt).decode("ascii")


def _is_user_in_group(conn: Connection, user_dn: str) -> bool:
    """Vérifie l'appartenance de l'utilisateur au groupe securechat."""
    conn.search(
        search_base=LDAP_GROUP_CN,
        search_filter=f"(member={user_dn})",
        search_scope=SUBTREE,
        attributes=["member"]
    )
    return len(conn.entries) > 0


def _next_uid_number(conn: Connection) -> str:
    """
    Retourne le prochain uidNumber disponible pour un nouvel utilisateur LDAP.
    """
    conn.search(
        search_base=LDAP_USERS_OU,
        search_filter="(uidNumber=*)",
        search_scope=SUBTREE,
        attributes=["uidNumber"]
    )

    existing = []
    for entry in conn.entries:
        try:
            existing.append(int(entry.uidNumber.value))
        except Exception:
            continue

    if not existing:
        return "1001"
    return str(max(existing) + 1)


# ─────────────────────────────────────────────
# FONCTIONS PUBLIQUES
# ─────────────────────────────────────────────

def authenticate_user(username: str, password: str) -> dict:
    """
    Authentifie un utilisateur via LDAPS (Bind LDAP).
    Appelée par le serveur de chat avant d'autoriser la connexion.

    Args:
        username : nom d'utilisateur (ex: "alice")
        password : mot de passe en clair (transitera chiffré via TLS)

    Returns:
        dict {"success": True, "dn": "...", "email": "...", "displayname": "..."}
        dict {"success": False, "error": "message d'erreur"}
    """
    try:
        user_dn = f"cn={username},{LDAP_USERS_OU}"

        if USE_MOCK_LDAP:
            user = _MOCK_USERS.get(username)
            if user and user["password"] == password:
                return {
                    "success":     True,
                    "dn":          user_dn,
                    "username":    username,
                    "email":       user["email"],
                    "displayname": user["displayname"]
                }
            return {"success": False, "error": "Utilisateur ou mot de passe incorrect"}

        tls = _get_ldap_tls()
        server = Server(LDAP_HOST, port=LDAP_PORT, use_ssl=True, tls=tls, get_info=ALL)

        # Étape 1 : admin cherche l'utilisateur (search and bind pattern)
        admin_conn = Connection(
            server,
            user=LDAP_ADMIN_DN,
            password=LDAP_ADMIN_PASS,
            authentication=SIMPLE,
            auto_bind=True
        )

        admin_conn.search(
            search_base=LDAP_USERS_OU,
            search_filter=f"(cn={username})",
            search_scope=SUBTREE,
            attributes=["cn", "mail", "displayName"]
        )

        if not admin_conn.entries:
            admin_conn.unbind()
            return {"success": False, "error": "Utilisateur introuvable"}

        entry     = admin_conn.entries[0]
        found_dn  = str(entry.entry_dn)

        # Étape 2 : vérifier appartenance au groupe
        if not _is_user_in_group(admin_conn, found_dn):
            admin_conn.unbind()
            logger.warning(f"Accès refusé pour {username} — pas dans le groupe securechat")
            return {"success": False, "error": "Accès non autorisé au groupe SecureChat"}

        admin_conn.unbind()

        # Étape 3 : vérifier le mot de passe via bind utilisateur
        user_conn = Connection(
            server,
            user=found_dn,
            password=password,
            authentication=SIMPLE,
            auto_bind=False
        )

        if not user_conn.bind():
            return {"success": False, "error": "Mot de passe incorrect"}

        user_conn.unbind()
        logger.info(f"Authentification réussie : {username}")

        return {
            "success":     True,
            "dn":          found_dn,
            "username":    username,
            "email":       str(entry.mail) if entry.mail else "",
            "displayname": str(entry.displayName) if entry.displayName else username
        }

    except LDAPBindError:
        logger.warning(f"Échec d'authentification pour {username} — mot de passe incorrect")
        return {"success": False, "error": "Mot de passe incorrect"}

    except LDAPSocketOpenError:
        logger.error(f"Impossible de joindre le serveur LDAP ({LDAP_HOST}:{LDAP_PORT})")
        return {"success": False, "error": "Serveur LDAP inaccessible"}

    except LDAPException as e:
        logger.error(f"Erreur LDAP inattendue : {e}")
        return {"success": False, "error": f"Erreur LDAP : {str(e)}"}


def add_user(username: str, password: str, email: str, displayname: str = None) -> dict:
    """
    Ajoute un nouvel utilisateur dans OpenLDAP et l'ajoute au groupe securechat.
    Refuse la création si l'username OU l'email existe déjà.

    Args:
        username    : identifiant (ex: "prof.dupont")
        password    : mot de passe initial
        email       : adresse email (ex: "dupont@efrei.fr")
        displayname : nom affiché (ex: "M. Dupont") — optionnel

    Returns:
        dict {"success": True}
        dict {"success": False, "error": "..."}
    """
    try:
        conn = _get_admin_connection()

        # ── PROTECTION ANTI-DOUBLONS ──────────────────────────
        # 1. Username déjà pris ?
        if _user_exists(conn, username):
            conn.unbind()
            logger.warning(f"Doublon username : {username}")
            return {"success": False, "error": f"L'utilisateur '{username}' existe déjà"}

        # 2. Email déjà utilisé ?
        if _email_exists(conn, email):
            conn.unbind()
            logger.warning(f"Doublon email : {email}")
            return {"success": False, "error": f"L'email '{email}' est déjà associé à un compte"}
        # ─────────────────────────────────────────────────────

        user_dn = f"cn={username},{LDAP_USERS_OU}"
        uid_number = _next_uid_number(conn)
        hashed_password = _hash_password(password)

        attrs = {
            "objectClass":   ["inetOrgPerson", "posixAccount", "shadowAccount"],
            "cn":            username,
            "sn":            username,
            "uid":           username,
            "mail":          email,
            "displayName":   displayname or username,
            "userPassword":  hashed_password,
            "uidNumber":     uid_number,
            "gidNumber":     uid_number,
            "homeDirectory": f"/home/{username}",
            "loginShell":    "/bin/bash"
        }

        success = conn.add(user_dn, attributes=attrs)

        if not success:
            conn.unbind()
            return {"success": False, "error": f"Échec création : {conn.result['description']}"}

        # Ajouter au groupe securechat sans écraser les autres membres
        conn.modify(
            LDAP_GROUP_CN,
            {"member": [(MODIFY_ADD, [user_dn])]}
        )

        conn.unbind()
        logger.info(f"Utilisateur créé : {username} ({email})")
        return {"success": True}

    except LDAPException as e:
        logger.error(f"Erreur création utilisateur {username} : {e}")
        return {"success": False, "error": str(e)}


def delete_user(username: str) -> dict:
    """
    Supprime un utilisateur de OpenLDAP.
    Vérifie que l'utilisateur existe avant de tenter la suppression.

    Args:
        username : identifiant à supprimer

    Returns:
        dict {"success": True} ou {"success": False, "error": "..."}
    """
    try:
        conn = _get_admin_connection()

        if not _user_exists(conn, username):
            conn.unbind()
            return {"success": False, "error": f"Utilisateur '{username}' introuvable"}

        user_dn = f"cn={username},{LDAP_USERS_OU}"
        success = conn.delete(user_dn)
        conn.unbind()

        if success:
            logger.info(f"Utilisateur supprimé : {username}")
            return {"success": True}
        else:
            return {"success": False, "error": f"Échec suppression : {conn.result['description']}"}

    except LDAPException as e:
        logger.error(f"Erreur suppression {username} : {e}")
        return {"success": False, "error": str(e)}


def list_users() -> list[dict]:
    """
    Retourne la liste de tous les utilisateurs du groupe securechat.
    Utilisée par l'UI pour afficher la barre latérale des contacts.

    Returns:
        Liste de dicts [{"username": "alice", "email": "...", "displayname": "..."}, ...]
    """
    if USE_MOCK_LDAP:
        users = [
            {"username": u, "email": d["email"], "displayname": d["displayname"]}
            for u, d in _MOCK_USERS.items()
        ]
        logger.info(f"{len(users)} utilisateur(s) mock trouvé(s)")
        return users

    try:
        conn = _get_admin_connection()

        conn.search(
            search_base=LDAP_USERS_OU,
            search_filter="(objectClass=inetOrgPerson)",
            search_scope=SUBTREE,
            attributes=["cn", "mail", "displayName"]
        )

        users = []
        for entry in conn.entries:
            users.append({
                "username":    str(entry.cn),
                "email":       str(entry.mail) if entry.mail else "",
                "displayname": str(entry.displayName) if entry.displayName else str(entry.cn)
            })

        conn.unbind()
        logger.info(f"{len(users)} utilisateur(s) trouvé(s)")
        return users

    except LDAPException as e:
        logger.error(f"Erreur liste utilisateurs : {e}")
        return []


def change_password(username: str, new_password: str) -> dict:
    """
    Change le mot de passe d'un utilisateur (action admin).
    Vérifie que l'utilisateur existe avant de modifier.

    Args:
        username     : identifiant
        new_password : nouveau mot de passe

    Returns:
        dict {"success": True} ou {"success": False, "error": "..."}
    """
    try:
        conn = _get_admin_connection()

        if not _user_exists(conn, username):
            conn.unbind()
            return {"success": False, "error": f"Utilisateur '{username}' introuvable"}

        user_dn = f"cn={username},{LDAP_USERS_OU}"
        conn.modify(user_dn, {"userPassword": [(MODIFY_REPLACE, [new_password])]})
        conn.unbind()

        logger.info(f"Mot de passe changé pour : {username}")
        return {"success": True}

    except LDAPException as e:
        logger.error(f"Erreur changement mot de passe {username} : {e}")
        return {"success": False, "error": str(e)}


# ─────────────────────────────────────────────
# SCRIPT D'ADMINISTRATION
# Lance : python ldap_auth.py
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import getpass

    print("=== ADMINISTRATION LDAP — SecureChat EFREI ===\n")
    print("1. Ajouter un utilisateur")
    print("2. Supprimer un utilisateur")
    print("3. Lister les utilisateurs")
    print("4. Changer un mot de passe")
    print("5. Tester une authentification")
    print("0. Quitter\n")

    choix = input("Choix : ").strip()

    if choix == "1":
        u = input("Username : ").strip()
        p = getpass.getpass("Mot de passe : ")
        e = input("Email : ").strip()
        d = input("Nom affiché (optionnel) : ").strip()
        result = add_user(u, p, e, d or None)
        print(f"\n→ {result}")

    elif choix == "2":
        u = input("Username à supprimer : ").strip()
        result = delete_user(u)
        print(f"\n→ {result}")

    elif choix == "3":
        users = list_users()
        if users:
            print(f"\n{len(users)} utilisateur(s) :\n")
            for user in users:
                print(f"  - {user['username']} | {user['email']} | {user['displayname']}")
        else:
            print("\nAucun utilisateur trouvé.")

    elif choix == "4":
        u = input("Username : ").strip()
        p = getpass.getpass("Nouveau mot de passe : ")
        result = change_password(u, p)
        print(f"\n→ {result}")

    elif choix == "5":
        u = input("Username : ").strip()
        p = getpass.getpass("Mot de passe : ")
        result = authenticate_user(u, p)
        print(f"\n→ {result}")

    elif choix == "0":
        print("Au revoir.")
    else:
        print("Choix invalide.")