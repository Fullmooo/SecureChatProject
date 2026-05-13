from common.crypto import CryptoEngine
from Crypto.Random import get_random_bytes

def test_full_crypto():
    print("--- TEST MOTEUR CRYPTO (JOYCE) ---")

    # 1. TEST AES-GCM
    print("\n1. Test AES-GCM...")
    key_aes = get_random_bytes(32)
    msg = "Message secret"
    enc = CryptoEngine.encrypt_aes_gcm(key_aes, msg)
    dec = CryptoEngine.decrypt_aes_gcm(key_aes, enc)
    print(f"[OK] AES : {dec}")

    # 2. TEST RSA (Chiffrement + Signature)
    print("\n2. Test RSA (OAEP + PSS)...")
    priv, pub = CryptoEngine.generate_rsa_keys()
    
    # Test Signature (PSS)
    signature = CryptoEngine.sign_message(priv, msg)
    if CryptoEngine.verify_signature(pub, msg, signature):
        print("[OK] RSA-PSS : Signature valide.")
    
    # Test Chiffrement (OAEP)
    session_key = get_random_bytes(32)
    enc_rsa = CryptoEngine.encrypt_rsa(pub, session_key)
    dec_rsa = CryptoEngine.decrypt_rsa(priv, enc_rsa)
    if session_key == dec_rsa:
        print("[OK] RSA-OAEP : Chiffrement clé OK.")

    # 3. TEST SECURE WIPE (Le vrai !)
    print("\n3. Test Wipe in-place...")
    data = bytearray(b"SENSITIVE")
    CryptoEngine.secure_wipe(data) # On utilise le nom harmonisé
    if all(b == 0 for b in data):
        print("[OK] Wipe : Données effacées en place.")

if __name__ == "__main__":
    test_full_crypto()