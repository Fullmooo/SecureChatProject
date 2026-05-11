from common.crypto import CryptoEngine
from Crypto.Random import get_random_bytes

def test_full_crypto():
    print("--- TEST DE LA PHASE 1.1 & 1.3 (JOYCE) ---")

    # --- TEST 1 : AES-GCM avec Assertion ---
    print("\n1. Test AES-GCM...")
    key_aes = get_random_bytes(32) # 256 bits
    secret_msg = "Ceci est un message ultra confidentiel."
    
    try:
        encrypted = CryptoEngine.encrypt_aes_gcm(key_aes, secret_msg)
        decrypted = CryptoEngine.decrypt_aes_gcm(key_aes, encrypted)
        if decrypted == secret_msg:
            print("[OK] AES-GCM : Chiffrement/Déchiffrement réussi.")
    except AssertionError as e:
        print(f"[ERREUR] L'assertion a échoué : {e}")

    # --- TEST 2 : RSA (Simulation échange de clé de session) ---
    print("\n2. Test RSA (Échange de clé)...")
    # Génération des clés du client (toi)
    priv_key, pub_key = CryptoEngine.generate_rsa_keys()
    
    # Le serveur génère une clé de session et la chiffre avec TA clé publique
    session_key_orig = get_random_bytes(32)
    encrypted_session_key = CryptoEngine.encrypt_rsa(pub_key, session_key_orig)
    
    # Toi (le client), tu la déchiffres avec ta clé privée
    session_key_recovered = CryptoEngine.decrypt_rsa(priv_key, encrypted_session_key)
    
    if session_key_orig == session_key_recovered:
        print("[OK] RSA : La clé de session a été récupérée avec succès.")

    # --- TEST 3 : Nettoyage Mémoire ---
    print("\n3. Test Zeroing...")
    buf = bytearray(b"Donnees Sensibles")
    CryptoEngine.secure_wipe(buf)
    if all(b == 0 for b in buf):
        print("[OK] RAM : Les données ont été effacées.")

if __name__ == "__main__":
    test_full_crypto()