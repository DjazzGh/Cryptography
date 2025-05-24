import secrets
import string

def generer_cle(taille):
    """Génère une clé aléatoire de la même longueur que le message en utilisant un générateur cryptographique."""
    return ''.join(secrets.choice(string.ascii_uppercase) for _ in range(taille))

def chiffrer_otp(texte_clair, cle):
    """Chiffre le texte clair en utilisant le chiffrement OTP."""
    if len(cle) < len(texte_clair):
        raise ValueError("La clé doit être au moins aussi longue que le texte clair.")
    
    texte_chiffre = []
    for lettre_clair, lettre_cle in zip(texte_clair, cle):
        if lettre_clair.isalpha():
            valeur_clair = ord(lettre_clair.upper()) - ord('A')
            valeur_cle = ord(lettre_cle.upper()) - ord('A')
            valeur_chiffree = (valeur_clair + valeur_cle) % 26
            texte_chiffre.append(chr(valeur_chiffree + ord('A')))
        else:
            texte_chiffre.append(lettre_clair)  # Conserve les caractères non alphabétiques
    return ''.join(texte_chiffre)

def dechiffrer_otp(texte_chiffre, cle):
    if len(cle) < len(texte_chiffre):
        raise ValueError("La clé doit être au moins aussi longue que le texte chiffré.")
    
    texte_dechiffre = []
    for lettre_chiffree, lettre_cle in zip(texte_chiffre, cle):
        if lettre_chiffree.isalpha():
            valeur_chiffree = ord(lettre_chiffree.upper()) - ord('A')
            valeur_cle = ord(lettre_cle.upper()) - ord('A')
            valeur_dechiffree = (valeur_chiffree - valeur_cle) % 26
            texte_dechiffre.append(chr(valeur_dechiffree + ord('A')))
        else:
            texte_dechiffre.append(lettre_chiffree)
    return ''.join(texte_dechiffre)


