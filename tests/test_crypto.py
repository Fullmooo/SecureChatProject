# test_crypto.py - Tests unitaires du module crypto.py
# Auteur : Lauraine - Tache 5.1

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.crypto import CryptoEngine


# TESTS AES-GCM

def test_aes_chiffrement_dechiffrement():
    """AES-GCM chiffre et dechiffre correctement un message."""
    cle = os.urandom(32)
    message = "Bonjour securisons !"
    chiffre = CryptoEngine.encrypt_aes_gcm(cle, message)
    dechiffre = CryptoEngine.decrypt_aes_gcm(cle, chiffre)
    assert dechiffre == message

def test_aes_mauvaise_cle():
    """Une mauvaise cle AES fait echouer le dechiffrement."""
    cle1 = os.urandom(32)
    cle2 = os.urandom(32)
    chiffre = CryptoEngine.encrypt_aes_gcm(cle1, "message secret")
    with pytest.raises(Exception):
        CryptoEngine.decrypt_aes_gcm(cle2, chiffre)

def test_aes_cle_mauvaise_taille():
    """Une cle AES de mauvaise taille leve une erreur."""
    cle_courte = os.urandom(16)
    with pytest.raises(Exception):
        CryptoEngine.encrypt_aes_gcm(cle_courte, "test")

def test_aes_chiffrement_different_a_chaque_fois():
    """Deux chiffrements du meme message donnent des resultats differents (nonce aleatoire)."""
    cle = os.urandom(32)
    message = "meme message"
    chiffre1 = CryptoEngine.encrypt_aes_gcm(cle, message)
    chiffre2 = CryptoEngine.encrypt_aes_gcm(cle, message)
    assert chiffre1 != chiffre2


# TESTS RSA-OAEP

def test_rsa_chiffrement_dechiffrement():
    """RSA-OAEP chiffre et dechiffre une cle AES correctement."""
    cle_privee, cle_publique = CryptoEngine.generate_rsa_keys()
    cle_aes = os.urandom(32)
    chiffre = CryptoEngine.encrypt_rsa(cle_publique, cle_aes)
    dechiffre = CryptoEngine.decrypt_rsa(cle_privee, chiffre)
    assert dechiffre == cle_aes

def test_rsa_mauvaise_cle_privee():
    """Une mauvaise cle privee RSA fait echouer le dechiffrement."""
    _, cle_publique = CryptoEngine.generate_rsa_keys()
    cle_privee_autre, _ = CryptoEngine.generate_rsa_keys()
    cle_aes = os.urandom(32)
    chiffre = CryptoEngine.encrypt_rsa(cle_publique, cle_aes)
    with pytest.raises(Exception):
        CryptoEngine.decrypt_rsa(cle_privee_autre, chiffre)

def test_rsa_generate_keys_retourne_deux_cles():
    """generate_rsa_keys retourne bien une paire (privee, publique)."""
    cle_privee, cle_publique = CryptoEngine.generate_rsa_keys()
    assert cle_privee is not None
    assert cle_publique is not None
    assert cle_privee != cle_publique


# TESTS SIGNATURE RSA-PSS

def test_signature_valide():
    """La signature RSA-PSS est verifiee correctement."""
    cle_privee, cle_publique = CryptoEngine.generate_rsa_keys()
    message = "message a signer"
    signature = CryptoEngine.sign_message(cle_privee, message)
    assert CryptoEngine.verify_signature(cle_publique, message, signature) == True

def test_signature_mauvaise_cle_publique():
    """Une mauvaise cle publique fait echouer la verification."""
    cle_privee, _ = CryptoEngine.generate_rsa_keys()
    _, autre_cle_publique = CryptoEngine.generate_rsa_keys()
    message = "message a signer"
    signature = CryptoEngine.sign_message(cle_privee, message)
    assert CryptoEngine.verify_signature(autre_cle_publique, message, signature) == False

def test_signature_message_modifie():
    """Un message modifie apres signature est detecte."""
    cle_privee, cle_publique = CryptoEngine.generate_rsa_keys()
    message = "message original"
    signature = CryptoEngine.sign_message(cle_privee, message)
    assert CryptoEngine.verify_signature(cle_publique, "message modifie", signature) == False


# TESTS UTILITAIRES

def test_secure_wipe_bytearray():
    """secure_wipe efface bien le contenu d'un bytearray."""
    data = bytearray(b"donnees sensibles")
    CryptoEngine.secure_wipe(data)
    assert data == bytearray(len(data))

def test_secure_wipe_liste():
    """secure_wipe met bien les elements d'une liste a zero."""
    data = [1, 2, 3, 4, 5]
    CryptoEngine.secure_wipe(data)
    assert all(x == 0 for x in data)