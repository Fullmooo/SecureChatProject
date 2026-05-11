import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from common.config import *  # noqa: E402,F403


if __name__ == "__main__":
    valider_config()  # noqa: F405
    print(f"Serveur      : {SERVER_HOST}:{SERVER_PORT}")  # noqa: F405
    print(f"LDAP port    : {LDAP_PORT}")  # noqa: F405
    print(f"Cle RSA      : {RSA_KEY_SIZE} bits")  # noqa: F405
    print(f"Dossier certs: {CERTS_DIR}")  # noqa: F405
