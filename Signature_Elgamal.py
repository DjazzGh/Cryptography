# Implémentation de la signature numérique ElGamal en Python

import random
import math

# Fonction utilitaire pour SHA-256 (corrigée)
def sha256(message):
    """Calcule le hachage SHA-256 d'un message."""
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    
    if isinstance(message, str):
        message = message.encode()
    orig_len = len(message) * 8
    message += b'\x80'
    while (len(message) % 64) != 56:
        message += b'\x00'
    message += orig_len.to_bytes(8, byteorder='big')
    
    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        w = [0] * 64  # Initialiser w avec 64 éléments
        for j in range(16):
            w[j] = int.from_bytes(chunk[j*4:j*4+4], 'big')
        for j in range(16, 64):
            s0 = (right_rotate(w[j-15], 7) ^ right_rotate(w[j-15], 18) ^ (w[j-15] >> 3))
            s1 = (right_rotate(w[j-2], 17) ^ right_rotate(w[j-2], 19) ^ (w[j-2] >> 10))
            w[j] = (w[j-16] + s0 + w[j-7] + s1) & 0xffffffff
        
        a, b, c, d, e, f, g, h_val = h
        for j in range(64):
            s0 = (right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22))
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (s0 + maj) & 0xffffffff
            s1 = (right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25))
            ch = (e & f) ^ (~e & g)
            t1 = (h_val + s1 + ch + K[j] + w[j]) & 0xffffffff
            h_val = g
            g = f
            f = e
            e = (d + t1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xffffffff
        
        h[0] = (h[0] + a) & 0xffffffff
        h[1] = (h[1] + b) & 0xffffffff
        h[2] = (h[2] + c) & 0xffffffff
        h[3] = (h[3] + d) & 0xffffffff
        h[4] = (h[4] + e) & 0xffffffff
        h[5] = (h[5] + f) & 0xffffffff
        h[6] = (h[6] + g) & 0xffffffff
        h[7] = (h[7] + h_val) & 0xffffffff
    
    return b''.join(h_val.to_bytes(4, byteorder='big') for h_val in h)

def right_rotate(x, n):
    """Rotation à droite de x sur n bits."""
    x &= 0xffffffff
    return ((x >> n) | (x << (32 - n))) & 0xffffffff

# Fonctions pour ElGamal
def is_prime(n, k=5):
    """Vérifie si n est premier en utilisant le test de Miller-Rabin."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
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
            n += 1
        if is_prime(n):
            return n

def mod_inverse(a, m):
    """Calcule l'inverse modulaire de a modulo m."""
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

def generate_elgamal_keys(bits=1024):
    """Génère une paire de clés ElGamal (publique et privée)."""
    p = generate_prime(bits)
    g = 2
    x = random.randint(1, p - 2)
    y = pow(g, x, p)
    return (p, g, y), x

def elgamal_sign(message, private_key, public_key):
    """Signe un message avec la clé privée ElGamal."""
    p, g, y = public_key
    x = private_key
    
    # Calculer le hachage SHA-256 du message
    hash_value = sha256(message)
    m = int.from_bytes(hash_value, 'big') % p
    
    # Choisir k aléatoire, premier avec p-1
    while True:
        k = random.randint(1, p - 2)
        if math.gcd(k, p - 1) == 1:
            break
    
    # Calculer r = g^k mod p
    r = pow(g, k, p)
    
    # Calculer k^-1 mod (p-1)
    k_inv = mod_inverse(k, p - 1)
    
    # Calculer s = (m - x*r) * k^-1 mod (p-1)
    s = ((m - x * r) * k_inv) % (p - 1)
    
    return (r, s)

def elgamal_verify(message, signature, public_key):
    """Vérifie une signature ElGamal avec la clé publique."""
    p, g, y = public_key
    r, s = signature
    
    # Vérifier que r est dans l'intervalle valide
    if not (0 < r < p):
        return False
    
    # Calculer le hachage SHA-256 du message
    hash_value = sha256(message)
    m = int.from_bytes(hash_value, 'big') % p
    
    # Vérifier : g^m ≡ y^r * r^s mod p
    left = pow(g, m, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p
    
    return left == right

# Exemple d'utilisation
if __name__ == "__main__":
    # Générer les clés ElGamal
    public_key, private_key = generate_elgamal_keys(bits=1024)
    p, g, y = public_key
    print(f"Clé publique (p, g, y) : ({p}, {g}, {y})")
    print(f"Clé privée (x) : {private_key}")
    
    # Message à signer
    message = "Bonjour, ElGamal Signature !"
    print(f"Message : {message}")
    
    # Signer le message
    signature = elgamal_sign(message, private_key, public_key)
    print(f"Signature (r, s) : {signature}")
    
    # Vérifier la signature
    is_valid = elgamal_verify(message, signature, public_key)
    print(f"Signature valide : {is_valid}")
    
    # Test avec un message modifié
    wrong_message = "Bonjour, ElGamal Signature Falsifié !"
    is_valid = elgamal_verify(wrong_message, signature, public_key)
    print(f"Signature valide (message modifié) : {is_valid}")