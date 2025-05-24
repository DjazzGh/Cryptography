import random
import math

def mod_inverse(a: int, m: int) -> int:
    """
    Calcule l'inverse modulaire de a modulo m (utilisant l'algorithme d'Euclide étendu).
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

def simple_sha256(message: bytes) -> int:
    """
    Version simplifiée de SHA-256 (pour démo uniquement, non sécurisée).
    Retourne un entier basé sur un hachage basique.
    """
    total = 0
    for i, byte in enumerate(message):
        total = (total + (byte * pow(31, i))) % (2**32)
    return total

def generate_dsa_parameters() -> tuple[int, int, int]:
    """
    Génère des paramètres DSA (p, q, g) simplifiés.
    Dans une implémentation réelle, p et q doivent être des nombres premiers.
    """
    # Valeurs simplifiées pour l'exemple (non sécurisées)
    q = 127  # Doit être un nombre premier dans une implémentation réelle
    p = 2047  # Doit être un nombre premier tel que (p-1) est divisible par q
    g = 3     # Générateur (doit être calculé correctement dans une implémentation réelle)
    return p, q, g

def generate_dsa_key_pair(p: int, q: int, g: int) -> tuple[int, int]:
    """
    Génère une paire de clés DSA (privée et publique).
    """
    private_key = random.randint(1, q - 1)
    public_key = pow(g, private_key, p)
    return private_key, public_key

def sign_message(message: bytes, private_key: int, p: int, q: int, g: int) -> tuple[int, int]:
    """
    Signe un message avec la clé privée DSA.
    """
    k = random.randint(1, q - 1)
    r = pow(g, k, p) % q
    if r == 0:
        raise ValueError("r = 0, choisir un autre k")
    
    k_inv = mod_inverse(k, q)
    h = simple_sha256(message)
    s = (k_inv * (h + private_key * r)) % q
    if s == 0:
        raise ValueError("s = 0, choisir un autre k")
    
    return r, s

def verify_signature(message: bytes, signature: tuple[int, int], public_key: int, p: int, q: int, g: int) -> bool:
    """
    Vérifie une signature DSA.
    """
    r, s = signature
    if not (0 < r < q and 0 < s < q):
        return False
    
    w = mod_inverse(s, q)
    h = simple_sha256(message)
    u1 = (h * w) % q
    u2 = (r * w) % q
    v = (pow(g, u1, p) * pow(public_key, u2, p) % p) % q
    
    return v == r

def main():
    # Générer les paramètres
    p, q, g = generate_dsa_parameters()
    
    # Générer les clés
    private_key, public_key = generate_dsa_key_pair(p, q, g)
    print(f"Clé privée: {private_key}")
    print(f"Clé publique: {public_key}")
    
    # Message à signer
    message = b"Bonjour, ceci est un message a signer!"
    
    # Signer le message
    signature = sign_message(message, private_key, p, q, g)
    print(f"Signature (r, s): {signature}")
    
    # Vérifier la signature
    is_valid = verify_signature(message, signature, public_key, p, q, g)
    print(f"Signature valide: {is_valid}")
    
    # Test avec un message corrompu
    wrong_message = b"Message corrompu!"
    is_valid = verify_signature(wrong_message, signature, public_key, p, q, g)
    print(f"Signature avec message corrompu: {is_valid}")

if __name__ == "__main__":
    main()