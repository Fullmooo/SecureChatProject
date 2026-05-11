import json
import base64
import time

class SecureProtocol:
    """
    Définit le format des messages échangés sur le réseau.
    Structure : { sender, type, timestamp, payload, signature }
    """
    
    # --- CONSTANTES DE TYPES DE MESSAGE ---
    # Centraliser ici permet d'éviter les erreurs de frappe dans le reste du projet
    TYPE_AUTH = "AUTH_REQ"
    TYPE_CSR = "CSR_SEND"       # Pour la demande de certificat
    TYPE_CHAT = "CHAT_MSG"
    TYPE_ROTATION = "KEY_ROTATION" # Pour le changement de clé AES
    
    @staticmethod
    def prepare_message(sender, message_type, data, signature=None):
        """
        Crée une structure de message standard avec timestamp et signature.
        data: texte ou bytes (sera encodé en Base64 si bytes)
        signature: bytes (sera encodé en Base64)
        """
        # Encodage des données binaires (payload)
        if isinstance(data, bytes):
            data = base64.b64encode(data).decode('utf-8')

        # Encodage de la signature binaire si elle existe
        encoded_sig = None
        if signature:
            encoded_sig = base64.b64encode(signature).decode('utf-8')

        packet = {
            "sender": sender,
            "type": message_type,
            "timestamp": time.time(),  # Ajout de l'heure précise
            "payload": data,
            "signature": encoded_sig     # Ajout de la preuve d'identité
        }
        
        return json.dumps(packet)

    @staticmethod
    def parse_message(json_string):
        """
        Décode un message JSON reçu. 
        Note : Les données à l'intérieur (payload/signature) restent en Base64 
        et devront être décodées par le CryptoEngine.
        """
        try:
            return json.loads(json_string)
        except json.JSONDecodeError:
            return None