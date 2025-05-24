# Implémentation de l'algorithme ElGamal en Python

import random
import math

def is_prime(n, k=5):
    """Vérifie si n est premier en utilisant le test de Miller-Rabin avec k itérations."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Écrire n-1 comme 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Test de Miller-Rabin
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """Génère un nombre premier de taille bits."""
    while True:
        n = random.getrandbits(bits)
        if n % 2 == 0:
            n += 1  # Assure que le nombre est impair
        if is_prime(n):
            return n

def generate_elgamal_keys(bits=1024):
    """Génère une paire de clés ElGamal (publique et privée)."""
    # Générer un grand nombre premier p
    p = generate_prime(bits)
    
    # Choisir un générateur g (souvent un petit nombre, ici 2 pour simplicité)
    g = 2
    
    # Choisir une clé privée x (aléatoire entre 1 et p-2)
    x = random.randint(1, p - 2)
    
    # Calculer la clé publique h = g^x mod p
    h = pow(g, x, p)
    
    # Clé publique : (p, g, h), Clé privée : x
    return (p, g, h), x

def elgamal_encrypt(message, public_key):
    """Chiffre le message avec la clé publique (p, g, h)."""
    p, g, h = public_key
    if isinstance(message, str):
        message = message.encode()
    
    # Convertir le message en nombre
    message_int = int.from_bytes(message, 'big')
    if message_int >= p:
        raise ValueError("Message trop grand pour la clé")
    
    # Choisir un k aléatoire (1 à p-2)
    k = random.randint(1, p - 2)
    
    # Calculer c1 = g^k mod p
    c1 = pow(g, k, p)
    
    # Calculer c2 = message * h^k mod p
    c2 = (message_int * pow(h, k, p)) % p
    
    return (c1, c2)

def elgamal_decrypt(ciphertext, private_key, p):
    """Déchiffre le texte chiffré avec la clé privée x et le module p."""
    c1, c2 = ciphertext
    x = private_key
    
    # Calculer s = c1^x mod p
    s = pow(c1, x, p)
    
    # Calculer l'inverse modulaire de s
    def mod_inverse(a, m):
        def egcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = egcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        gcd, x, _ = egcd(a, m)
        if gcd != 1:
            raise ValueError("L'inverse modulaire n'existe pas")
        return x % m
    
    s_inv = mod_inverse(s, p)
    
    # Calculer message = c2 * s^-1 mod p
    message_int = (c2 * s_inv) % p
    
    # Convertir le résultat en bytes
    byte_length = (message_int.bit_length() + 7) // 8
    message = message_int.to_bytes(byte_length, 'big')
    return message

# Exemple d'utilisation
if __name__ == "__main__":
    # Générer les clés ElGamal (1024 bits pour cet exemple)
    public_key, private_key = generate_elgamal_keys(bits=1024)
    p, g, h = public_key
    print(f"Clé publique (p, g, h) : ({p}, {g}, {h})")
    print(f"Clé privée (x) : {private_key}")
    
    # Message à chiffrer
    message = "Bonjour, ElGamal !"
    print(f"Message original : {message}")
    
    # Chiffrement
    ciphertext = elgamal_encrypt(message, public_key)
    print(f"Texte chiffré (c1, c2) : {ciphertext}")
    
    # Déchiffrement
    decrypted = elgamal_decrypt(ciphertext, private_key, p)
    print(f"Message déchiffré : {decrypted.decode()}")