# test_session_pki.py - Tests unitaires session_pki.py
# Auteur : Lauraine — Tâche 5.1

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
import client.session_pki as pki


# TESTS — generer_cle_privee()

def test_cle_est_rsa(tmp_path, monkeypatch):
    """La clé générée est bien de type RSA."""
    monkeypatch.setattr(pki, "CLIENT_CERTS_DIR", str(tmp_path))
    monkeypatch.setattr(pki, "CLIENT_KEY_PATH", str(tmp_path / "client_key.pem"))
    cle = pki.generer_cle_privee()
    assert isinstance(cle, rsa.RSAPrivateKey)

def test_cle_taille_4096(tmp_path, monkeypatch):
    """La clé RSA fait bien 4096 bits."""
    monkeypatch.setattr(pki, "CLIENT_CERTS_DIR", str(tmp_path))
    monkeypatch.setattr(pki, "CLIENT_KEY_PATH", str(tmp_path / "client_key.pem"))
    cle = pki.generer_cle_privee()
    assert cle.key_size == 4096

def test_cle_fichier_cree(tmp_path, monkeypatch):
    """Le fichier de clé privée est bien créé sur le disque."""
    key_path = str(tmp_path / "client_key.pem")
    monkeypatch.setattr(pki, "CLIENT_CERTS_DIR", str(tmp_path))
    monkeypatch.setattr(pki, "CLIENT_KEY_PATH", key_path)
    pki.generer_cle_privee()
    assert os.path.exists(key_path)


# TESTS — creer_csr()

def test_csr_format_pem(tmp_path, monkeypatch):
    """La CSR est bien au format PEM."""
    monkeypatch.setattr(pki, "CLIENT_CERTS_DIR", str(tmp_path))
    monkeypatch.setattr(pki, "CLIENT_KEY_PATH", str(tmp_path / "client_key.pem"))
    cle = pki.generer_cle_privee()
    csr_bytes = pki.creer_csr("lauraine", cle)
    assert csr_bytes.startswith(b"-----BEGIN CERTIFICATE REQUEST-----")

def test_csr_contient_username(tmp_path, monkeypatch):
    """La CSR contient bien le nom d'utilisateur dans le Common Name."""
    monkeypatch.setattr(pki, "CLIENT_CERTS_DIR", str(tmp_path))
    monkeypatch.setattr(pki, "CLIENT_KEY_PATH", str(tmp_path / "client_key.pem"))
    cle = pki.generer_cle_privee()
    csr_bytes = pki.creer_csr("lauraine", cle)
    csr = x509.load_pem_x509_csr(csr_bytes)
    cn = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    assert cn == "lauraine"


# TESTS — sauvegarder_certificat()

def test_sauvegarder_certificat_cree_fichier(tmp_path, monkeypatch):
    """Le certificat est bien sauvegardé sur le disque."""
    cert_path = str(tmp_path / "client_cert.pem")
    monkeypatch.setattr(pki, "CLIENT_CERTS_DIR", str(tmp_path))
    monkeypatch.setattr(pki, "CLIENT_CERT_PATH", cert_path)
    faux_cert = b"-----BEGIN CERTIFICATE-----\nfakedata\n-----END CERTIFICATE-----\n"
    pki.sauvegarder_certificat(faux_cert)
    assert os.path.exists(cert_path)


# TESTS — charger_credentials()

def test_charger_credentials_sans_fichiers(tmp_path, monkeypatch):
    """Retourne (None, None) si aucun certificat n'existe."""
    monkeypatch.setattr(pki, "CLIENT_KEY_PATH", str(tmp_path / "inexistant.pem"))
    monkeypatch.setattr(pki, "CLIENT_CERT_PATH", str(tmp_path / "inexistant_cert.pem"))
    cle, cert = pki.charger_credentials()
    assert cle is None
    assert cert is None


# TEST D'INTÉGRATION — enrôlement 

def test_enrolement(tmp_path, monkeypatch):
    """
    Test d'intégration : enrôlement PKI complet.
    Génération clé → CSR → signature CA → certificat sauvegardé.
    """
    monkeypatch.setattr(pki, "CLIENT_CERTS_DIR", str(tmp_path))
    monkeypatch.setattr(pki, "CLIENT_KEY_PATH", str(tmp_path / "client_key.pem"))
    monkeypatch.setattr(pki, "CLIENT_CERT_PATH", str(tmp_path / "client_cert.pem"))

    cle, cert = pki.enroler_client("lauraine_test", connexion_serveur=None)

    assert cle is not None
    assert cert is not None
    assert isinstance(cert, x509.Certificate)
    cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    assert cn == "lauraine_test"