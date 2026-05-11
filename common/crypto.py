from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

class CryptoEngine:
    
    @staticmethod
    def encrypt_aes_gcm(key, plaintext):
        assert len(key) == 32, f"Clé AES invalide : {len(key)} octets"
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        return cipher.nonce + tag + ciphertext

    @staticmethod
    def decrypt_aes_gcm(key, encrypted_data):
        assert len(key) == 32, f"Clé AES invalide : {len(key)} octets"
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
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

    @staticmethod
    def secure_wipe(var):
        if isinstance(var, (bytearray, bytes)):
            ba = bytearray(var)
            for i in range(len(ba)):
                ba[i] = 0