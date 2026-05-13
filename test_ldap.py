import sys
sys.path.insert(0, '.')
from server.ldap_auth import authenticate_user, list_users

print("=== TEST AUTHENTIFICATION ===")
r = authenticate_user("segolene", "mdp_segolene")
print(f"segolene bon mdp    : {r}")

r2 = authenticate_user("segolene", "mauvaismdp")
print(f"segolene mauvais mdp: {r2}")

r3 = authenticate_user("joyce", "mdp_joyce")
print(f"joyce bon mdp       : {r3}")

print()
print("=== LISTE MEMBRES ===")
users = list_users()
for u in users:
    print(f"  - {u['username']} | {u['email']}")
