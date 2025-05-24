

def rc4(cle, texte_clair):
    # Convertir la clé et le texte clair en bytes si ce sont des chaînes
    if isinstance(cle, str):
        cle = cle.encode()
    if isinstance(texte_clair, str):
        texte_clair = texte_clair.encode()
    
    # Initialiser le tableau d'état et le tableau temporaire 
    S = list(range(256))
    T = []
    longueur_cle = len(cle)
    
    # Algorithme de planification de clé (KSA)
    for i in range(256):
        T.append(cle[i % longueur_cle])
    
    j = 0
    for i in range(256):
        j = (j + S[i] + T[i]) % 256
        S[i], S[j] = S[j], S[i]  
    
    # Algorithme de génération pseudo-aléatoire (PRGA)
    i = j = 0
    flux_cle = []
    
    for _ in range(len(texte_clair)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  
        k = S[(S[i] + S[j]) % 256]
        flux_cle.append(k)
    
    # Effectuer un XOR entre le texte clair et le flux de clés pour produire le texte chiffré
    texte_chiffre = []
    for p, k in zip(texte_clair, flux_cle):
        texte_chiffre.append(p ^ k)
    
    return bytes(texte_chiffre)

