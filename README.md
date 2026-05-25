# ChatSec - Messagerie Sécurisée d'Entreprise

Application de messagerie de groupe chiffrée, développée en Python dans le cadre de l'UE Professionnelle — Rattrapage 2026, Efrei Paris Panthéon-Assas.

---

## Sommaire

1. [Prérequis](#1-prérequis)
2. [Structure du projet](#2-structure-du-projet)
3. [Configuration réseau (ZeroTier)](#3-configuration-réseau-zerotier)
4. [Lancer le serveur LDAP (Docker)](#4-lancer-le-serveur-ldap-docker)
5. [Lancer le serveur](#5-lancer-le-serveur)
6. [Lancer le client (mode développement)](#6-lancer-le-client-mode-développement)
7. [Lancer le client (exécutable .exe)](#7-lancer-le-client-exécutable-exe)
8. [Première connexion](#8-première-connexion)
9. [Repartir à zéro (supprimer l'historique)](#9-repartir-à-zéro-supprimer-lhistorique)
10. [Recompiler l'exécutable .exe](#10-recompiler-lexécutable-exe)
11. [Dépannage](#11-dépannage)

---

## 1. Prérequis

### Machine qui fait tourner le serveur

| Logiciel | Version minimale | Remarque |
|----------|-----------------|----------|
| Python | 3.10+ | Avec pip |
| Docker | 20.10+ | Pour le conteneur OpenLDAP |
| OpenLDAP | 2.6+ | Déjà configuré dans le conteneur Docker `chatsec-ldap` |
| ZeroTier | dernière version | L'IP du serveur sur ZeroTier doit être `10.211.57.223` |

### Machines clientes (mode développement Python)

| Logiciel | Version minimale |
|----------|-----------------|
| Python | 3.10+ |
| ZeroTier | dernière version (rejoindre le même réseau) |

### Machines clientes (mode .exe)

Aucun prérequis — l'exécutable `ChatSec.exe` embarque tout.  
ZeroTier doit quand même être installé pour accéder au réseau.

### Dépendances Python (serveur + client en mode dev)

```bash
pip install cryptography customtkinter ldap3 pillow
```

---

## 2. Structure du projet

```
SecureChatProject/
├── client/
│   ├── main_client.py          # Point d'entrée client
│   ├── session_pki.py          # Génération clé RSA + CSR
│   ├── db_manager.py           # SQLite chiffré (historique)
│   └── ui/
│       ├── login_frame.py      # Écran de connexion
│       └── chat_frame.py       # Interface de messagerie
├── server/
│   ├── main_server.py          # Point d'entrée serveur
│   ├── ldap_auth.py            # Authentification LDAP + script admin
│   ├── generate_ldap_cert.py   # Génération certificat LDAP
│   └── pki/
│       └── ca_manager.py       # Autorité de certification interne
│   └── certs/
│       ├── ca_cert.pem         # Certificat CA (public — partagé avec les clients)
│       └── ca_private_key.pem  # Clé privée CA   NE PAS PARTAGER
├── common/
│   ├── config.py               # Configuration centrale (IP, ports, chemins)
│   ├── crypto.py               # Primitives AES-256 GCM + RSA-4096
│   └── protocol.py             # Framing TCP + sérialisation JSON
├── dist/
│   └── ChatSec.exe             # Exécutable client Windows compilé
└── README.md
```

---

## 3. Configuration réseau (ZeroTier)

Toutes les machines (serveur + clients) doivent être sur le **même réseau ZeroTier**.

1. Installer ZeroTier : https://www.zerotier.com/download/
2. Rejoindre le réseau de l'équipe avec la commande :
   ```bash
   zerotier-cli join <NETWORK_ID>
   ```
3. Vérifier que la machine serveur a bien l'IP `10.211.57.223` dans ZeroTier.

> Si l'IP du serveur change, modifier `SERVER_HOST` dans `common/config.py` **avant** de recompiler le .exe.

---

## 4. Lancer le serveur LDAP (Docker)
> La procedure pour mettre en place le serveur LDAP est dans LDAP_SETUP.md
> Le serveur LDAP doit être démarré **avant** le serveur applicatif.  
> Il tourne dans un conteneur Docker nommé `chatsec-ldap`.

### Démarrer le conteneur LDAP

```bash
docker start chatsec-ldap
```

Pour vérifier qu'il est bien démarré :

```bash
docker ps
```

Vous devez voir une ligne avec `chatsec-ldap` et l'état `Up`.

> Si le conteneur n'existe pas encore (première installation), le créer avec :
> ```bash
> docker run -d \
>   --name chatsec-ldap \
>   -p 636:636 \
>   --restart unless-stopped \
>   osixia/openldap:latest
> ```
> Puis appliquer la configuration LDAP de l'équipe (contacter l'administrateur).

### Arrêter le conteneur LDAP

```bash
docker stop chatsec-ldap
```

### Gérer les utilisateurs LDAP

Un script interactif permet d'administrer les comptes sans connaître les commandes LDAP :

```bash
cd SecureChatProject
python server/ldap_auth.py
```

Le menu propose :
- `1` — Ajouter un utilisateur
- `2` — Supprimer un utilisateur
- `3` — Lister les utilisateurs
- `4` — Changer le mot de passe d'un utilisateur
- `5` — Tester l'authentification d'un utilisateur

> Ce script ne fonctionne que sur la machine serveur (connexion locale au conteneur Docker).

---

## 5. Lancer le serveur

> Le serveur applicatif doit être lancé **après** le serveur LDAP et **avant** tout client.

```bash
cd SecureChatProject
python server/main_server.py
```

Le serveur affiche dans la console :

```
[SERVER] CA chargée.
[SERVER] Écoute sur 0.0.0.0:5000 (TLS 1.3)
[SERVER] Surveillance LDAP active.
```

Le serveur tourne en continu. Laisser la fenêtre ouverte.  
Pour l'arrêter : `Ctrl+C`.

> **Le serveur n'a pas besoin d'être redémarré entre deux sessions.**  
> Il suffit de le laisser tourner.

---

## 6. Lancer le client (mode développement)

```bash
cd SecureChatProject
python client/main_client.py
```

La fenêtre de connexion s'ouvre.

---

## 7. Lancer le client (exécutable .exe)

1. Copier `dist/ChatSec.exe` sur la machine cliente.
2. Double-cliquer sur `ChatSec.exe`.

> **Important :** ne pas déplacer le .exe dans un dossier nécessitant des droits administrateur.  
> L'application crée un dossier `storage\` à côté du .exe pour stocker les clés et l'historique.

Structure générée automatiquement au premier lancement :

```
ChatSec.exe
storage\
    certs\          ← clé RSA et certificat X.509 du client
    messages.db     ← historique chiffré
```

---

## 8. Première connexion

1. Lancer l'application (Python ou .exe).
2. Entrer son **identifiant LDAP** (ex : `segolene`) et son **mot de passe LDAP**.
3. Cliquer sur **Se connecter**.

Ce qui se passe automatiquement :
- Si c'est la **première connexion** : une clé RSA-4096 est générée et un certificat X.509 est signé par le serveur CA.
- La clé AES-256 de groupe est reçue du serveur (chiffrée avec la clé publique RSA du client).
- Les messages manqués pendant la déconnexion sont chargés (buffer serveur, max 50 messages).

> Les identifiants doivent exister dans l'annuaire OpenLDAP du serveur.  
> Contacter l'administrateur LDAP pour créer ou modifier un compte (`python server/ldap_auth.py`).

---

## 9. Repartir à zéro (supprimer l'historique)

### Mode .exe (clientes)

Supprimer le dossier `storage\` qui se trouve **à côté du .exe** :

```
ChatSec.exe
storage\      ← supprimer ce dossier
```

Ensuite relancer le .exe — tout repart proprement.

### Mode Python (développement)

Supprimer :
```bash
# Historique et clés client
rm -rf storage/

# Certificats générés localement (optionnel)
rm -rf common/certs/
rm -rf client/certs/
```

### Côté serveur

Supprimer le buffer en mémoire en **redémarrant le serveur** (`Ctrl+C` puis relancer).  
Les certificats CA dans `server/certs/` ne doivent **pas** être supprimés (ils sont partagés avec tous les clients via le .exe).

---

## 10. Recompiler l'exécutable .exe

> Nécessaire uniquement si le code source a été modifié.

```bash
cd SecureChatProject
python -m PyInstaller --onefile --windowed \
  --collect-all customtkinter \
  --collect-all Crypto \
  --add-data "server/certs/ca_cert.pem;server/certs" \
  --icon icon.ico \
  --name ChatSec \
  client/main_client.py
```

Le nouveau `ChatSec.exe` apparaît dans `dist/`.  
**Fermer l'application avant de recompiler** (sinon `PermissionError`).

Après recompilation, envoyer le nouveau `dist/ChatSec.exe` aux coéquipières avec les instructions :
1. Supprimer `storage\` à côté de l'ancien .exe.
2. Supprimer l'ancien .exe.
3. Remplacer par le nouveau .exe.

---

## 11. Dépannage

| Symptôme | Cause probable | Solution |
|----------|---------------|----------|
| `Connexion refusée` | Serveur non démarré | Lancer `python server/main_server.py` |
| `Connexion refusée` | ZeroTier non connecté | Vérifier ZeroTier + IP `10.211.57.223` |
| `Identifiants incorrects` | Conteneur LDAP arrêté | `docker start chatsec-ldap` |
| `Identifiants incorrects` | Mauvais login/mot de passe LDAP | Vérifier avec `python server/ldap_auth.py` → option 5 |
| Messages en double à la reconnexion | Ancien `storage\` + nouveau serveur | Supprimer `storage\`, relancer |
| .exe ne s'ouvre pas | Antivirus bloquant | Ajouter une exception pour `ChatSec.exe` |
| `PermissionError` à la recompilation | Le .exe est en cours d'exécution | Fermer l'application, puis recompiler |
| Horodatage incorrect | Heure système désynchronisée | Vérifier l'heure Windows (synchronisation NTP) |
| `docker: command not found` | Docker non installé | Installer Docker Desktop : https://www.docker.com/products/docker-desktop |

---

## Informations techniques

| Paramètre | Valeur |
|-----------|--------|
| IP serveur (ZeroTier) | `10.211.57.223` |
| Port applicatif | `5000` (TCP) |
| Port LDAP | `636` (LDAPS) |
| Chiffrement canal | TLS 1.3 |
| Chiffrement messages | AES-256 GCM |
| Transport de clé | RSA-4096 OAEP |
| Signature | RSA-PSS SHA-256 |
| Stockage local | SQLite chiffré PBKDF2 + AES-256 GCM |
| Annuaire | OpenLDAP dans Docker (`chatsec-ldap`) |

---

## Équipe

| Membre | Phases |
|--------|--------|
| Ségolène DOMCHE DJOUEGO DJUIGA | Phase 2 : Serveur TCP/TLS — Phase 4 : Interface UI |
| Joyce Fortune Dolce GUIAKAM DJOKO GAPIN'SI | Phase 1 : Cryptographie — Phase 3 : PKI client |
| Louise ETONDÈ MOUKOKO | Phase 1 : Configuration — Phase 3 : Gestion des clés |
| Louise Morelle TAJEFOT WAMBA | Phase 2 : Auth LDAP — Phase 3 : SQLite chiffré |

---

*UE Professionnelle — Rattrapage 2026 — Efrei Paris Panthéon-Assas*
