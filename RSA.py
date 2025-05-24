# Implémentation de l'algorithme RSA en Python

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

def mod_inverse(e, phi):
    """Calcule l'inverse modulaire de e modulo phi (algorithme d'Euclide étendu)."""
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = egcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    gcd, x, _ = egcd(e, phi)
    if gcd != 1:
        raise ValueError("L'inverse modulaire n'existe pas")
    return x % phi

def generate_rsa_keys(bits=1024):
    """Génère une paire de clés RSA (publique et privée)."""
    # Générer deux nombres premiers distincts p et q
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while p == q:
        q = generate_prime(bits // 2)
    
    # Calculer n = p * q et phi = (p-1) * (q-1)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Choisir e (souvent 65537, un nombre premier de Fermat)
    e = 65537
    while math.gcd(e, phi) != 1:
        e = random.randint(3, phi - 1)
    
    # Calculer d, l'inverse modulaire de e modulo phi
    d = mod_inverse(e, phi)
    
    # Clé publique : (e, n), Clé privée : (d, n)
    return (e, n), (d, n)

def rsa_encrypt(message, public_key):
    """Chiffre le message avec la clé publique (e, n)."""
    e, n = public_key
    if isinstance(message, str):
        message = message.encode()
    
    # Convertir le message en nombre et chiffrer
    message_int = int.from_bytes(message, 'big')
    if message_int >= n:
        raise ValueError("Message trop grand pour la clé")
    ciphertext = pow(message_int, e, n)
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    """Déchiffre le texte chiffré avec la clé privée (d, n)."""
    d, n = private_key
    # Déchiffrer et convertir le résultat en bytes
    message_int = pow(ciphertext, d, n)
    # Calculer la longueur en bytes nécessaire
    byte_length = (message_int.bit_length() + 7) // 8
    message = message_int.to_bytes(byte_length, 'big')
    return message

# Exemple d'utilisation
if __name__ == "__main__":
    # Générer les clés RSA (1024 bits pour cet exemple)
    public_key, private_key = generate_rsa_keys(bits=1024)
    print(f"Clé publique (e, n) : {public_key}")
    print(f"Clé privée (d, n) : {private_key}")
    
    # Message à chiffrer
    message = "Bonjour, RSA !"
    print(f"Message original : {message}")
    
    # Chiffrement
    ciphertext = rsa_encrypt(message, public_key)
    print(f"Texte chiffré : {ciphertext}")
    
    # Déchiffrement
    decrypted = rsa_decrypt(ciphertext, private_key)
    print(f"Message déchiffré : {decrypted.decode()}")