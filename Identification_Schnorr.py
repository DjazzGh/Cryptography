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

def generate_parameters() -> tuple[int, int, int, int, int]:
    """
    Génère les paramètres publics p, q, g et une paire de clés (x, y).
    Retourne (p, q, g, x, y) où y = g^x mod p.
    Utilise des nombres premiers fixes pour simplifier (non sécurisé).
    """
    p = 467  # Nombre premier (petit pour la démonstration)
    q = 233  # Nombre premier, ordre du sous-groupe (q divise p-1)
    g = 2    # Générateur (simplifié)
    x = random.randint(1, q - 1)  # Clé privée
    y = pow(g, x, p)  # Clé publique
    return p, q, g, x, y

def prover_commitment(p: int, q: int, g: int) -> tuple[int, int]:
    """
    Étape d'engagement : génère k et r = g^k mod p.
    """
    k = random.randint(1, q - 1)
    r = pow(g, k, p)
    return k, r

def prover_response(k: int, x: int, c: int, q: int) -> int:
    """
    Étape de réponse : calcule s = k + c * x mod q.
    """
    s = (k + c * x) % q
    return s

def verifier_check(g: int, s: int, r: int, y: int, c: int, p: int) -> bool:
    """
    Étape de vérification : vérifie si g^s == r * y^c mod p.
    """
    left = pow(g, s, p)
    right = (r * pow(y, c, p)) % p
    return left == right

def schnorr_protocol(p: int, q: int, g: int, x: int, y: int) -> bool:
    """
    Exécute le protocole d'identification de Schnorr.
    
    Args:
        p: Nombre premier (modulus)
        q: Ordre du sous-groupe
        g: Générateur
        x: Clé privée
        y: Clé publique (g^x mod p)
    Returns:
        True si la vérification réussit, False sinon
    """
    # Étape 1 : Engagement
    k, r = prover_commitment(p, q, g)
    print(f"Engagement: r = {r}")
    
    # Étape 2 : Défi
    c = random.randint(0, q - 1)
    print(f"Défi: c = {c}")
    
    # Étape 3 : Réponse
    s = prover_response(k, x, c, q)
    print(f"Réponse: s = {s}")
    
    # Étape 4 : Vérification
    result = verifier_check(g, s, r, y, c, p)
    print(f"Vérification: {'réussie' if result else 'échouée'}")
    return result

def main():
    # Générer les paramètres
    p, q, g, x, y = generate_parameters()
    print(f"Paramètres: p = {p}, q = {q}, g = {g}, x (privé) = {x}, y (public) = {y}")
    
    # Exécuter le protocole avec la bonne clé privée
    print("\nExécution du protocole Schnorr (bonne clé privée):")
    result = schnorr_protocol(p, q, g, x, y)
    
    # Résultat final
    if result:
        print("\nIdentification réussie : le prouveur connaît la clé privée !")
    else:
        print("\nIdentification échouée : le prouveur ne connaît pas la clé privée.")
    
    # Test avec une mauvaise clé privée (simulation d'un attaquant)
    print("\nTest avec une mauvaise clé privée:")
    bad_x = (x + 1) % q  # Clé privée incorrecte
    result = schnorr_protocol(p, q, g, bad_x, y)
    if result:
        print("\nIdentification réussie (ce qui ne devrait pas arriver avec une mauvaise clé) !")
    else:
        print("\nIdentification échouée : le prouveur ne connaît pas la bonne clé privée.")

if __name__ == "__main__":
    main()