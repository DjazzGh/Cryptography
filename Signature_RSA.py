import random
import math

# Fonction utilitaire pour SHA-256
def right_rotate(x, n):
    """Rotation à droite de x sur n bits."""
    x &= 0xffffffff
    return ((x >> n) | (x << (32 - n))) & 0xffffffff

def to_bytes(n, length):
    """Convertit un entier en bytes (big-endian)."""
    return n.to_bytes(length, byteorder='big')

def from_bytes(b):
    """Convertit des bytes en entier (big-endian)."""
    return int.from_bytes(b, byteorder='big')

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
    message += to_bytes(orig_len, 8)
    
    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        w = [from_bytes(chunk[j:j+4]) for j in range(0, 64, 4)]
        w.extend([0] * (64 - len(w)))  # Extend w to 64 elements
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
    
    return b''.join(to_bytes(h_val, 4) for h_val in h)

# Fonctions RSA
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

def mod_inverse(e, phi):
    """Calcule l'inverse modulaire de e modulo phi."""
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
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while p == q:
        q = generate_prime(bits // 2)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537
    while math.gcd(e, phi) != 1:
        e = random.randint(3, phi - 1)
    
    d = mod_inverse(e, phi)
    return (e, n), (d, n)

def rsa_sign(message, private_key):
    """Signe un message avec la clé privée RSA."""
    d, n = private_key
    # Calculer le hachage SHA-256 du message
    hash_value = sha256(message)
    hash_int = int.from_bytes(hash_value, 'big')
    # Vérifier que le hachage est inférieur à n
    if hash_int >= n:
        raise ValueError("Hachage trop grand pour la clé")
    # Signer : signature = hash^d mod n
    signature = pow(hash_int, d, n)
    return signature

def rsa_verify(message, signature, public_key):
    """Vérifie une signature RSA avec la clé publique."""
    e, n = public_key
    # Calculer le hachage SHA-256 du message
    hash_value = sha256(message)
    hash_int = int.from_bytes(hash_value, 'big')
    # Vérifier : hash = signature^e mod n
    computed_hash = pow(signature, e, n)
    return computed_hash == hash_int

# Exemple d'utilisation
if __name__ == "__main__":
    # Générer les clés RSA
    public_key, private_key = generate_rsa_keys(bits=1024)
    print(f"Clé publique (e, n) : {public_key}")
    print(f"Clé privée (d, n) : {private_key}")
    
    # Message à signer
    message = "Bonjour, RSA Signature !"
    print(f"Message : {message}")
    
    # Signer le message
    signature = rsa_sign(message, private_key)
    print(f"Signature : {signature}")
    
    # Vérifier la signature
    is_valid = rsa_verify(message, signature, public_key)
    print(f"Signature valide : {is_valid}")
    
    # Test avec un message modifié
    wrong_message = "Bonjour, RSA Signature Falsifié !"
    is_valid = rsa_verify(wrong_message, signature, public_key)
    print(f"Signature valide (message modifié) : {is_valid}")