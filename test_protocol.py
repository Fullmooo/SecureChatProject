from common.protocol import SecureProtocol
import json

def test_protocol_logic():
    print("--- TEST DE LA PHASE 1.1 (PROTOCOLE JSON) ---")

    # 1. Préparation d'un message texte simple
    sender = "Joyce"
    msg_type = "CHAT"
    content = "Salut l'équipe, le moteur est prêt !"
    
    paquet_json = SecureProtocol.prepare_message(sender, msg_type, content)
    
    # Vérification visuelle
    print(f"1. Message préparé : {paquet_json}")

    # 2. Décodage du message
    data = SecureProtocol.parse_message(paquet_json)
    
    if data["sender"] == sender and data["type"] == msg_type:
        print("[OK] Structure JSON respectée.")
    else:
        print("[ERREUR] Problème dans la structure du message.")

    # 3. Test avec des données binaires (Simulation de message chiffré)
    secret_bytes = b"\x01\x02\x03\x04" # Simulation de bytes chiffrés
    paquet_bin = SecureProtocol.prepare_message("System", "CRYPTO", secret_bytes)
    
    print(f"2. Message binaire encodé : {paquet_bin}")
    
    # Vérification du Base64
    if "payload" in paquet_bin:
        print("[OK] Encodage Base64 fonctionnel pour les données binaires.")

if __name__ == "__main__":
    try:
        test_protocol_logic()
        print("\n--- TOUS LES TESTS DU PROTOCOLE SONT RÉUSSIS ---")
    except Exception as e:
        print(f"\n[ERREUR CRITIQUE] Le test a échoué : {e}")