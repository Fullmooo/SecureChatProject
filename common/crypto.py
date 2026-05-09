from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

class CryptoEngine:
    """
    Moteur de sécurité du projet SecureChat.
    Gère le chiffrement, la signature et la sécurité de la RAM.
    """

    # --- PARTIE 1 : RSA (IDENTITÉ) ---
    @staticmethod
    def generate_rsa_keypair():
        """Génère RSA-4096 pour l'Étape 0"""
        key = RSA.generate(4096)
        return key.export_key(), key.publickey().export_key()

    @staticmethod
    def sign_message(private_key_pem, message_bytes):
        """Signe les données pour l'Étape 2"""
        key = RSA.import_key(private_key_pem)
        h = SHA256.new(message_bytes)
        return pss.new(key).sign(h)

    @staticmethod
    def verify_signature(public_key_pem, message_bytes, signature):
        """Vérifie l'origine (Étape 3)"""
        key = RSA.import_key(public_key_pem)
        h = SHA256.new(message_bytes)
        verifier = pss.new(key)
        try:
            verifier.verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    # --- PARTIE 2 : AES (CONFIDENTIALITÉ) ---
    @staticmethod
    def encrypt_aes_gcm(key, plaintext):
        """Chiffre en AES-256 GCM"""
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
        return cipher.nonce, ciphertext, tag

    @staticmethod
    def decrypt_aes_gcm(key, nonce, ciphertext, tag):
        """Déchiffre et valide l'intégrité"""
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')

    # --- PARTIE 3 : ANTI-FORENSICS ---
    @staticmethod
    def secure_wipe(secret):
        """Efface physiquement les données de la RAM (Zeroing)"""
        if isinstance(secret, bytearray):
            for i in range(len(secret)):
                secret[i] = 0