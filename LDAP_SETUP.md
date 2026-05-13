# Guide de Configuration du Serveur LDAP — ChatSec

Ce guide explique comment installer Docker, configurer WSL2 et lancer
le serveur LDAP sécurisé (LDAPS) utilisé pour l'authentification du projet.

---

## Prérequis

- Windows 10/11
- Droits administrateur sur la machine
- Connexion Internet pour les téléchargements

---

## Étape 1 — Installer WSL2

Ouvrir **PowerShell en tant qu'administrateur** et lancer :

```powershell
wsl --install
```

> Si Ubuntu échoue à se télécharger, continuer quand même — on l'installera
> autrement à l'étape suivante.

**Redémarrer le PC.**

---

## Étape 2 — Activer le Hyperviseur Windows

Sans cette étape, Docker ne démarre pas. Dans PowerShell **administrateur** :

```powershell
bcdedit /set hypervisorlaunchtype auto
```

**Redémarrer le PC.**

---

## Étape 3 — Installer Ubuntu (WSL2)

```powershell
winget install Canonical.Ubuntu.2404
ubuntu2404.exe
```

Créer un nom d'utilisateur et mot de passe Linux quand demandé, puis fermer
la fenêtre Ubuntu (`exit`).

---

## Étape 4 — Installer Docker Desktop

Télécharger la version **4.28.0** (version stable recommandée) :

```
https://desktop.docker.com/win/main/amd64/139021/Docker%20Desktop%20Installer.exe
```

Installer puis **redémarrer le PC**.

Vérifier que Docker fonctionne :

```powershell
docker run hello-world
```

Si Docker ne démarre pas, vérifier l'étape 2.

---

## Étape 5 — Générer les Certificats LDAP

Le serveur LDAP utilise LDAPS (port 636) avec des certificats signés par
notre Root CA. Depuis la racine du projet :

```powershell
# 1. Générer le Root CA (si pas déjà fait)
python server/pki/ca_manager.py

# 2. Générer le certificat du serveur LDAP signé par notre CA
python server/generate_ldap_cert.py
```

Les fichiers suivants seront créés dans `server/certs/` :
- `ca_cert.pem` — certificat public du CA
- `ca_private_key.pem` — clé privée du CA **(ne jamais partager)**
- `ldap_server_cert.pem` — certificat du serveur LDAP
- `ldap_server_key.pem` — clé privée LDAP **(ne jamais partager)**

---

## Étape 6 — Lancer le Serveur LDAP (Docker)

```powershell
$certDir = "CHEMIN_ABSOLU_VERS_LE_PROJET\server\certs"
docker run --name chatsec-ldap `
  -p 636:636 `
  -v "${certDir}\ldap_server_cert.pem:/container/service/slapd/assets/certs/ldap.crt" `
  -v "${certDir}\ldap_server_key.pem:/container/service/slapd/assets/certs/ldap.key" `
  -v "${certDir}\ca_cert.pem:/container/service/slapd/assets/certs/ca.crt" `
  -e LDAP_ORGANISATION="ChatSec" `
  -e LDAP_DOMAIN="chatsec.local" `
  -e LDAP_ADMIN_PASSWORD="Pyproject@237" `
  -e LDAP_TLS_CRT_FILENAME=ldap.crt `
  -e LDAP_TLS_KEY_FILENAME=ldap.key `
  -e LDAP_TLS_CA_CRT_FILENAME=ca.crt `
  -e LDAP_TLS_VERIFY_CLIENT=never `
  --detach osixia/openldap
```

> Remplacer `CHEMIN_ABSOLU_VERS_LE_PROJET` par le chemin réel sur votre machine.
> Exemple : `D:\ING2-School_TP\ChatSec\SecureChatProject`

---

## Étape 7 — Créer les Utilisateurs LDAP

```powershell
$ldif = @"
dn: ou=users,dc=chatsec,dc=local
objectClass: organizationalUnit
ou: users

dn: ou=groups,dc=chatsec,dc=local
objectClass: organizationalUnit
ou: groups

dn: cn=securechat,ou=groups,dc=chatsec,dc=local
objectClass: groupOfNames
cn: securechat
member: cn=segolene,ou=users,dc=chatsec,dc=local
member: cn=joyce,ou=users,dc=chatsec,dc=local
member: cn=lauraine,ou=users,dc=chatsec,dc=local
member: cn=morelle,ou=users,dc=chatsec,dc=local

dn: cn=segolene,ou=users,dc=chatsec,dc=local
objectClass: inetOrgPerson
cn: segolene
sn: segolene
uid: segolene
mail: segolene.domche-djouego-djuiga@efrei.net
displayName: Segolene
userPassword: mdp_segolene

dn: cn=joyce,ou=users,dc=chatsec,dc=local
objectClass: inetOrgPerson
cn: joyce
sn: joyce
uid: joyce
mail: joyce-fortune-dolce.guiakam-djoko-gapin.-si@efrei.net
displayName: Joyce
userPassword: mdp_joyce

dn: cn=lauraine,ou=users,dc=chatsec,dc=local
objectClass: inetOrgPerson
cn: lauraine
sn: lauraine
uid: lauraine
mail: louise.etonde-moukoko@efrei.net
displayName: Lauraine
userPassword: mdp_lauraine

dn: cn=morelle,ou=users,dc=chatsec,dc=local
objectClass: inetOrgPerson
cn: morelle
sn: morelle
uid: morelle
mail: louise-morelle.tajefot-wamba@efrei.net
displayName: Morelle
userPassword: mdp_morelle
"@
[System.IO.File]::WriteAllText("$env:TEMP\users.ldif", $ldif, [System.Text.Encoding]::ASCII)
docker cp "$env:TEMP\users.ldif" chatsec-ldap:/tmp/users.ldif
docker exec chatsec-ldap ldapadd -x -D "cn=admin,dc=chatsec,dc=local" -w "Pyproject@237" -f /tmp/users.ldif
```

---

## Étape 8 — Tester l'Authentification

Installer les dépendances Python :

```powershell
pip install -r requirements.txt
```

Lancer le test :

```powershell
python test_ldap.py
```

Résultat attendu :
```
segolene bon mdp    : {'success': True, ...}
segolene mauvais mdp: {'success': False, 'error': 'Mot de passe incorrect'}
joyce bon mdp       : {'success': True, ...}
4 utilisateur(s) trouvé(s)
```

---

## Commandes Utiles

```powershell
# Voir si le conteneur tourne
docker ps

# Arrêter le conteneur
docker stop chatsec-ldap

# Relancer le conteneur (après un redémarrage PC)
docker start chatsec-ldap

# Voir les logs du serveur LDAP
docker logs chatsec-ldap

# Lister les utilisateurs LDAP
docker exec chatsec-ldap ldapsearch -x `
  -D "cn=admin,dc=chatsec,dc=local" -w "Pyproject@237" `
  -b "ou=users,dc=chatsec,dc=local" "(objectClass=inetOrgPerson)" cn mail
```

---

## Configuration LDAP dans le Code

Dans `server/ldap_auth.py` :

```python
USE_MOCK_LDAP = True   # Mode développement sans Docker
USE_MOCK_LDAP = False  # Mode réel avec Docker LDAP (étapes 5-7 requises)
```

---

## Dépannage

| Problème | Solution |
|---|---|
| `hypervisorlaunchtype Off` | Refaire l'étape 2 et redémarrer |
| `No certificate was found` | Vérifier que les certificats sont générés (étape 5) |
| `Serveur LDAP inaccessible` | Vérifier que Docker tourne : `docker ps` |
| `Utilisateur introuvable` | Refaire l'étape 7 pour créer les utilisateurs |
| Docker bloqué au démarrage | Fermer et relancer Docker Desktop |
