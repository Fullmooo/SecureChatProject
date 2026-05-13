from common.protocol import SecureProtocol
import json

def test_protocol():
    print("\n--- TEST PROTOCOLE RÉSEAU ---")
    
    sender = "Joyce"
    payload = "Salut l'équipe !"
    # On simule une signature bidon (en bytes)
    fake_sig = b"signature_test_123"
    
    # Test avec signature
    json_msg = SecureProtocol.prepare_message(
        sender, 
        SecureProtocol.TYPE_CHAT, 
        payload, 
        signature=fake_sig
    )
    
    data = json.loads(json_msg)
    
    # Vérifications des nouveaux champs
    if "timestamp" in data and "signature" in data:
        print(f"[OK] Structure : Timestamp et Signature présents.")
        print(f"[OK] Type : {data['type']}")
        print(f"[OK] Payload : {data['payload']}")
    else:
        print("[ERREUR] Champs manquants dans le protocole.")

if __name__ == "__main__":
    test_protocol()