import random
import math

def mod_inverse(a: int, m: int) -> int:
    """
    Calcule l'inverse modulaire de a modulo m (algorithme d'Euclide étendu).
    """
    def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("L'inverse modulaire n'existe pas")
    return (x % m + m) % m

def generate_parameters() -> tuple[int, int]:
    """
    Génère les paramètres publics n = p * q et un secret s.
    Retourne (n, v, s) où v = s^2 mod n.
    Utilise des nombres premiers fixes pour simplifier (non sécurisé).
    """
    p = 101  # Nombre premier (petit pour la démonstration)
    q = 103  # Nombre premier
    n = p * q  # n = 101 * 103 = 10403
    s = random.randint(1, n - 1)  # Secret du prouveur
    v = (s * s) % n  # Clé publique
    return n, v, s

def prover_commitment(n: int) -> tuple[int, int]:
    """
    Étape d'engagement : génère r et x = r^2 mod n.
    """
    r = random.randint(1, n - 1)
    x = (r * r) % n
    return r, x

def prover_response(r: int, s: int, b: int, n: int) -> int:
    """
    Étape de réponse : calcule y = r * s^b mod n.
    """
    if b == 0:
        y = r
    else:  # b == 1
        y = (r * s) % n
    return y

def verifier_check(x: int, y: int, v: int, b: int, n: int) -> bool:
    """
    Étape de vérification : vérifie si y^2 == x * v^b mod n.
    """
    left = (y * y) % n
    right = (x * pow(v, b, n)) % n
    return left == right

def feige_fiat_shamir_protocol(n: int, v: int, s: int, t: int = 3) -> bool:
    """
    Exécute le protocole Feige-Fiat-Shamir pour t itérations.
    
    Args:
        n: Modulus public (p * q)
        v: Clé publique (s^2 mod n)
        s: Secret du prouveur
        t: Nombre d'itérations
    Returns:
        True si toutes les itérations réussissent, False sinon
    """
    for i in range(t):
        # Étape 1 : Engagement
        r, x = prover_commitment(n)
        print(f"Itération {i+1} - Engagement: x = {x}")
        
        # Étape 2 : Défi
        b = random.randint(0, 1)
        print(f"Itération {i+1} - Défi: b = {b}")
        
        # Étape 3 : Réponse
        y = prover_response(r, s, b, n)
        print(f"Itération {i+1} - Réponse: y = {y}")
        
        # Étape 4 : Vérification
        if not verifier_check(x, y, v, b, n):
            print(f"Itération {i+1} - Vérification échouée")
            return False
        print(f"Itération {i+1} - Vérification réussie")
    
    return True

def main():
    # Générer les paramètres
    n, v, s = generate_parameters()
    print(f"Paramètres: n = {n}, v = {v}, secret s = {s}")
    
    # Exécuter le protocole avec t=3 itérations
    print("\nExécution du protocole Feige-Fiat-Shamir:")
    result = feige_fiat_shamir_protocol(n, v, s, t=3)
    
    # Résultat final
    if result:
        print("\nIdentification réussie : le prouveur connaît le secret !")
    else:
        print("\nIdentification échouée : le prouveur ne connaît pas le secret.")
    
    # Test avec un mauvais secret (simulation d'un attaquant)
    print("\nTest avec un mauvais secret:")
    bad_s = (s + 1) % n  # Secret incorrect
    result = feige_fiat_shamir_protocol(n, v, bad_s, t=3)
    if result:
        print("\nIdentification réussie (ce qui ne devrait pas arriver avec un mauvais secret) !")
    else:
        print("\nIdentification échouée : le prouveur ne connaît pas le bon secret.")

if __name__ == "__main__":
    main()