import json
import base64

class SecureProtocol:
    """
    Définit le format des messages échangés sur le réseau.
    Transforme les objets Python en JSON sécurisé.
    """

    @staticmethod
    def prepare_message(sender, message_type, data):
        """
        Crée une structure de message standard.
        data: peut être du texte ou des octets (bytes)
        """
        # Si les données sont des octets (chiffrement), on les encode en Base64 pour le JSON
        if isinstance(data, bytes):
            data = base64.b64encode(data).decode('utf-8')

        packet = {
            "sender": sender,
            "type": message_type,
            "payload": data
        }
        return json.dumps(packet)

    @staticmethod
    def parse_message(json_string):
        """Décode un message JSON reçu"""
        return json.loads(json_string)