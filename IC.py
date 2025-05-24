import string
from collections import Counter

def clean_text(text):
    """Nettoie le texte : met en majuscules et supprime les caractères non alphabétiques."""
    return ''.join(c for c in text.upper() if c.isalpha())

def index_of_coincidence(text):
    """Calcule l'indice de coïncidence pour un texte donné."""
    text = clean_text(text)
    n = len(text)
    
    if n < 2:
        return 0.0  # Évite la division par zéro pour les textes trop courts
    
    # Calcul des fréquences des lettres
    freq = Counter(text)   
    # Calcul de l'indice de coïncidence
    ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
    return ic


text = "HELLO WORLD"
ic = index_of_coincidence(text)
print(f"Index of Coincidence: {ic:.4f}")
print(f"Expected IC for English: ~0.0667")
