from common.crypto import CryptoEngine
from Crypto.Random import get_random_bytes

# 1. Préparation d'une clé AES en bytearray (pour pouvoir l'effacer après)
cle_aes = bytearray(get_random_bytes(32)) 

print("--- TEST DE LA PHASE 1.1 (JOYCE) ---")

# Test du chiffrement
try:
    nonce, cipher, tag = CryptoEngine.encrypt_aes_gcm(cle_aes, "Ceci est un secret")
    clair = CryptoEngine.decrypt_aes_gcm(cle_aes, nonce, cipher, tag)
    print(f"[OK] AES-GCM fonctionnel : {clair}")
except Exception as e:
    print(f"[ERREUR] AES : {e}")

# Test de l'effacement RAM
CryptoEngine.secure_wipe(cle_aes)
if all(b == 0 for b in cle_aes):
    print("[OK] Zeroing Memory : La clé a été effacée de la RAM.")