# Implémentation de l'échange de clés Diffie-Hellman en Python

import random

def diffie_hellman():
    # Paramètres publics : un grand nombre premier p et une base g
    p = 23  # Nombre premier (dans la pratique, utiliser un nombre beaucoup plus grand)
    g = 5   # Générateur (base)

    # Étape 1 : Alice choisit une clé privée aléatoire
    a = random.randint(1, p-1)  # Clé privée d'Alice
    A = pow(g, a, p)  # Clé publique d'Alice : g^a mod p

    # Étape 2 : Bob choisit une clé privée aléatoire
    b = random.randint(1, p-1)  # Clé privée de Bob
    B = pow(g, b, p)  # Clé publique de Bob : g^b mod p

    # Étape 3 : Échange des clés publiques
    # (Dans la réalité, Alice envoie A à Bob et Bob envoie B à Alice)

    # Étape 4 : Calcul de la clé secrète partagée
    # Alice calcule la clé partagée : B^a mod p
    shared_key_alice = pow(B, a, p)
    # Bob calcule la clé partagée : A^b mod p
    shared_key_bob = pow(A, b, p)

    # Vérification : les deux clés partagées doivent être identiques
    assert shared_key_alice == shared_key_bob, "Les clés partagées ne correspondent pas !"

    return {
        "p": p,
        "g": g,
        "private_key_alice": a,
        "public_key_alice": A,
        "private_key_bob": b,
        "public_key_bob": B,
        "shared_secret": shared_key_alice
    }

# Exemple d'utilisation
if __name__ == "__main__":
    result = diffie_hellman()
    print(f"Nombre premier (p) : {result['p']}")
    print(f"Générateur (g) : {result['g']}")
    print(f"Clé privée d'Alice : {result['private_key_alice']}")
    print(f"Clé publique d'Alice : {result['public_key_alice']}")
    print(f"Clé privée de Bob : {result['private_key_bob']}")
    print(f"Clé publique de Bob : {result['public_key_bob']}")
    print(f"Clé secrète partagée : {result['shared_secret']}")