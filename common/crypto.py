from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

class CryptoEngine:
    
    # --- AES-GCM (Messages) ---
    @staticmethod
    def encrypt_aes_gcm(key, plaintext):
        assert len(key) == 32, "Clé AES doit faire 32 octets"
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        return cipher.nonce + tag + ciphertext

    @staticmethod
    def decrypt_aes_gcm(key, encrypted_data):
        assert len(key) == 32, "Clé AES doit faire 32 octets"
        nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

    # --- C'EST CETTE PARTIE QUI MANQUE OU EST MAL NOMMÉE ---
    @staticmethod
    def generate_rsa_keys():
        key = RSA.generate(4096)
        return key.export_key(), key.publickey().export_key()

    @staticmethod
    def encrypt_rsa(public_key_data, data):
        recipient_key = RSA.import_key(public_key_data)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        return cipher_rsa.encrypt(data)

    @staticmethod
    def decrypt_rsa(private_key_data, encrypted_data):
        recipient_key = RSA.import_key(private_key_data)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        return cipher_rsa.decrypt(encrypted_data)

    # --- RSA PSS (Signature - LE RETOUR) ---
    @staticmethod
    def sign_message(private_key_data, message):
        key = RSA.import_key(private_key_data)
        h = SHA256.new(message.encode('utf-8'))
        signature = pss.new(key).sign(h)
        return signature

    @staticmethod
    def verify_signature(public_key_data, message, signature):
        try:
            key = RSA.import_key(public_key_data)
            h = SHA256.new(message.encode('utf-8'))
            verifier = pss.new(key)
            verifier.verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    # --- SÉCURITÉ ---
    # --- SÉCURITÉ ---
    @staticmethod
    def generate_rsa_keys():
        """Génère un couple de clés RSA 4096 bits"""
        key = RSA.generate(4096)
        return key.export_key(), key.publickey().export_key()

    @staticmethod
    def secure_wipe(var):
        """Efface VRAIMENT la mémoire de l'objet original"""
        if isinstance(var, bytearray):
            # Le [:] est magique : il modifie le contenu de l'original en RAM
            var[:] = b'\x00' * len(var)
        elif isinstance(var, list):
            for i in range(len(var)):
                var[i] = 0