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
    Génère les paramètres publics p, q, g et une paire de clés (x, h).
    Retourne (p, q, g, x, h) où h = g^x mod p.
    Utilise des nombres premiers fixes pour simplifier (non sécurisé).
    """
    p = 467  # Nombre premier (petit pour la démonstration)
    q = 233  # Nombre premier, ordre du sous-groupe (q divise p-1)
    g = 2    # Générateur (simplifié)
    x = random.randint(1, q - 1)  # Clé privée
    h = pow(g, x, p)  # Clé publique
    return p, q, g, x, h

def elgamal_encrypt(message: int, p: int, q: int, g: int, h: int) -> tuple[int, int]:
    """
    Chiffre un message avec ElGamal.
    
    Args:
        message: Message en clair (entier < p)
        p: Nombre premier (modulus)
        q: Ordre du sous-groupe
        g: Générateur
        h: Clé publique (g^x mod p)
    Returns:
        Tuple (c1, c2) représentant le chiffré
    """
    if message >= p:
        raise ValueError("Le message doit être inférieur à p")
    k = random.randint(1, q - 1)
    c1 = pow(g, k, p)
    c2 = (pow(h, k, p) * message) % p
    return c1, c2

def elgamal_decrypt(cipher: tuple[int, int], x: int, p: int) -> int:
    """
    Déchiffre un message chiffré avec ElGamal.
    
    Args:
        cipher: Tuple (c1, c2) représentant le chiffré
        x: Clé privée
        p: Nombre premier (modulus)
    Returns:
        Message en clair
    """
    c1, c2 = cipher
    s = pow(c1, x, p)
    s_inv = mod_inverse(s, p)
    message = (c2 * s_inv) % p
    return message

def elgamal_multiply(cipher1: tuple[int, int], cipher2: tuple[int, int], p: int) -> tuple[int, int]:
    """
    Effectue une multiplication homomorphe sur deux chiffrés.
    
    Args:
        cipher1: Premier chiffré (c1, c2)
        cipher2: Deuxième chiffré (d1, d2)
        p: Nombre premier (modulus)
    Returns:
        Chiffré du produit des messages
    """
    c1, c2 = cipher1
    d1, d2 = cipher2
    return (c1 * d1) % p, (c2 * d2) % p

def main():
    # Générer les paramètres
    p, q, g, x, h = generate_parameters()
    print(f"Paramètres: p = {p}, q = {q}, g = {g}, x (privé) = {x}, h (public) = {h}")
    
    # Chiffrer deux messages
    m1 = 42
    m2 = 17
    print(f"\nMessages en clair: m1 = {m1}, m2 = {m2}")
    
    cipher1 = elgamal_encrypt(m1, p, q, g, h)
    cipher2 = elgamal_encrypt(m2, p, q, g, h)
    print(f"Chiffré de m1: {cipher1}")
    print(f"Chiffré de m2: {cipher2}")
    
    # Déchiffrer pour vérifier
    decrypted_m1 = elgamal_decrypt(cipher1, x, p)
    decrypted_m2 = elgamal_decrypt(cipher2, x, p)
    print(f"Déchiffré de cipher1: {decrypted_m1}")
    print(f"Déchiffré de cipher2: {decrypted_m2}")
    
    # Démontrer la propriété homomorphe multiplicative
    print("\nDémonstration de la propriété homomorphe:")
    product_cipher = elgamal_multiply(cipher1, cipher2, p)
    print(f"Chiffré du produit: {product_cipher}")
    decrypted_product = elgamal_decrypt(product_cipher, x, p)
    expected_product = (m1 * m2) % p
    print(f"Déchiffré du produit: {decrypted_product}")
    print(f"Produit attendu (m1 * m2 mod p): {expected_product}")
    print(f"Propriété homomorphe vérifiée: {decrypted_product == expected_product}")

