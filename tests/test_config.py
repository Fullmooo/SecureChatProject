# test_config.py - Tests unitaires du module config.py
# Auteur : Lauraine — Tâche 5.1


import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common import config

# TESTS RÉSEAU

def test_server_host_est_defini():
    """L'adresse du serveur est bien une chaîne non vide."""
    assert isinstance(config.SERVER_HOST, str)
    assert len(config.SERVER_HOST) > 0

def test_server_port_valide():
    """Le port serveur est entre 1 et 65535."""
    assert isinstance(config.SERVER_PORT, int)
    assert 1 <= config.SERVER_PORT <= 65535

def test_ldap_port_valide():
    """Le port LDAPS est entre 1 et 65535."""
    assert isinstance(config.LDAP_PORT, int)
    assert 1 <= config.LDAP_PORT <= 65535

def test_timeout_positif():
    """Le timeout doit être strictement positif."""
    assert config.TIMEOUT > 0

# TESTS CHEMINS

def test_base_dir_existe():
    """Le dossier racine du projet existe bien sur le disque."""
    assert os.path.exists(config.BASE_DIR)

def test_ca_cert_path_format_pem():
    """Le chemin vers le certificat CA se termine en .pem."""
    assert config.CA_CERT_PATH.endswith(".pem")

def test_client_key_path_format_pem():
    """Le chemin vers la clé privée se termine en .pem."""
    assert config.CLIENT_KEY_PATH.endswith(".pem")

def test_client_cert_path_format_pem():
    """Le chemin vers le certificat client se termine en .pem."""
    assert config.CLIENT_CERT_PATH.endswith(".pem")


# TESTS DE CRYPTOGRAPHIE


def test_rsa_key_size_suffisant():
    """La taille de clé RSA doit être au moins 4096 bits."""
    assert config.RSA_KEY_SIZE >= 4096

def test_aes_key_size_correct():
    """La taille de clé AES doit être 256 bits."""
    assert config.AES_KEY_SIZE == 256

# TESTS valider_config()

def test_valider_config_retourne_true():
    """La validation passe avec une config correcte."""
    assert config.valider_config() == True

def test_valider_config_cree_dossier(tmp_path, monkeypatch):
    """valider_config() crée le dossier certs s'il n'existe pas."""
    faux_dossier = str(tmp_path / "faux_certs")
    monkeypatch.setattr(config, "CERTS_DIR", faux_dossier)
    config.valider_config()
    assert os.path.exists(faux_dossier)

def test_valider_config_port_invalide(monkeypatch):
    """Un port invalide doit lever une ValueError."""
    monkeypatch.setattr(config, "SERVER_PORT", 99999)
    with pytest.raises(ValueError):
        config.valider_config()

def test_valider_config_timeout_invalide(monkeypatch):
    """Un timeout négatif doit lever une ValueError."""
    monkeypatch.setattr(config, "TIMEOUT", -5)
    with pytest.raises(ValueError):
        config.valider_config()