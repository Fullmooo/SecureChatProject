from common.crypto import CryptoEngine
from Crypto.Random import get_random_bytes

def test_full_crypto():
    print("--- TEST DE LA PHASE 1.1 & 1.3 (JOYCE) ---")

    # 1. TEST AES
    print("\n1. Test AES-GCM...")
    key_aes = get_random_bytes(32)
    msg = "Message secret de Joyce"
    try:
        enc = CryptoEngine.encrypt_aes_gcm(key_aes, msg)
        dec = CryptoEngine.decrypt_aes_gcm(key_aes, enc)
        print(f"[OK] AES : {dec}")
    except Exception as e:
        print(f"[ERREUR] AES : {e}")

    # 2. TEST RSA
    print("\n2. Test RSA...")
    try:
        priv, pub = CryptoEngine.generate_rsa_keys()
        session_key = get_random_bytes(32)
        enc_rsa = CryptoEngine.encrypt_rsa(pub, session_key)
        dec_rsa = CryptoEngine.decrypt_rsa(priv, enc_rsa)
        if session_key == dec_rsa:
            print("[OK] RSA : Clé de session récupérée.")
    except Exception as e:
        print(f"[ERREUR] RSA : {e}")

    # 3. TEST WIPE
    print("\n3. Test Wipe...")
    data = bytearray(b"SENSITIVE")
    CryptoEngine.secure_wipe(data)
    if all(b == 0 for b in data):
        print("[OK] Wipe : Mémoire nettoyée.")

if __name__ == "__main__":
    test_full_crypto()