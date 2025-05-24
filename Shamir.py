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

def generate_prime() -> int:
    """
    Retourne un nombre premier fixe pour l'exemple (simplifié, non sécurisé).
    Dans une implémentation réelle, générer un grand nombre premier.
    """
    return 10007  # Nombre premier pour les calculs modulo

def evaluate_polynomial(coefficients: list[int], x: int, modulus: int) -> int:
    """
    Évalue un polynôme aux coefficients donnés en x modulo modulus.
    """
    result = 0
    for coef in reversed(coefficients):
        result = (result * x + coef) % modulus
    return result

def generate_shares(secret: int, n: int, k: int, modulus: int) -> list[tuple[int, int]]:
    """
    Génère n parts du secret avec un seuil k.
    
    Args:
        secret: Le secret à partager (entier)
        n: Nombre de parts à générer
        k: Seuil (nombre minimum de parts pour reconstruire)
        modulus: Nombre premier pour les calculs
    Returns:
        Liste de tuples (x, y) représentant les parts
    """
    if k > n:
        raise ValueError("Le seuil k doit être inférieur ou égal à n")
    if secret >= modulus:
        raise ValueError("Le secret doit être inférieur au modulus")
    
    # Créer un polynôme de degré k-1 avec le secret comme terme constant
    coefficients = [secret] + [random.randint(1, modulus - 1) for _ in range(k - 1)]
    
    # Générer n points (x, y) où y = P(x)
    shares = []
    for x in range(1, n + 1):
        y = evaluate_polynomial(coefficients, x, modulus)
        shares.append((x, y))
    
    return shares

def lagrange_interpolation(shares: list[tuple[int, int]], modulus: int) -> int:
    """
    Reconstruit le secret à partir de k parts ou plus en utilisant l'interpolation de Lagrange.
    
    Args:
        shares: Liste de tuples (x, y) représentant les parts
        modulus: Nombre premier pour les calculs
    Returns:
        Le secret reconstruit
    """
    secret = 0
    k = len(shares)
    
    for i in range(k):
        xi, yi = shares[i]
        numerator = denominator = 1
        for j in range(k):
            if i != j:
                xj = shares[j][0]
                numerator = (numerator * (0 - xj)) % modulus
                denominator = (denominator * (xi - xj)) % modulus
        
        # Calculer le coefficient de Lagrange
        term = (yi * numerator * mod_inverse(denominator, modulus)) % modulus
        secret = (secret + term) % modulus
    
    return secret

def main():
    # Paramètres
    secret = 1234  # Secret à partager
    n = 5          # Nombre de parts
    k = 3          # Seuil
    modulus = generate_prime()
    
    print(f"Secret original: {secret}")
    
    # Générer les parts
    shares = generate_shares(secret, n, k, modulus)
    print(f"Parts générées: {shares}")
    
    # Reconstruire le secret avec k parts
    selected_shares = shares[:k]
    reconstructed_secret = lagrange_interpolation(selected_shares, modulus)
    print(f"Secret reconstruit avec {k} parts: {reconstructed_secret}")
    
    # Tester avec moins de k parts (devrait échouer ou donner un résultat incorrect)
    if k > 1:
        insufficient_shares = shares[:k-1]
        result = lagrange_interpolation(insufficient_shares, modulus)
        print(f"Résultat avec {k-1} parts (incorrect): {result}")
    
    # Tester avec un ensemble différent de k parts
    different_shares = shares[1:k+1]
    reconstructed_secret = lagrange_interpolation(different_shares, modulus)
    print(f"Secret reconstruit avec un autre ensemble de {k} parts: {reconstructed_secret}")

if __name__ == "__main__":
    main()