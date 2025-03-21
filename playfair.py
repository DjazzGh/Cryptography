import string

def generer_tableau_cle(mot_clef):
    """Génère une table de chiffrement 5x5 à partir du mot-clé."""
    mot_clef = mot_clef.upper().replace('J', 'I')
    lettres_utilisees = []
    
    # Ajout des lettres uniques du mot-clé
    for lettre in mot_clef:
        if lettre.isalpha() and lettre not in lettres_utilisees:
            lettres_utilisees.append(lettre)

    # Ajout des lettres restantes de l'alphabet (sans 'J')
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for lettre in alphabet:
        if lettre not in lettres_utilisees:
            lettres_utilisees.append(lettre)

    # Construction du tableau 5x5
    return [lettres_utilisees[i:i+5] for i in range(0, 25, 5)]

def creer_dictionnaire_positions(tableau_cle):
    """Crée un dictionnaire associant chaque lettre à sa position (ligne, colonne)."""
    positions = {}
    for ligne in range(5):
        for colonne in range(5):
            lettre = tableau_cle[ligne][colonne]
            positions[lettre] = (ligne, colonne)
    positions['J'] = positions['I']  # 'J' est traité comme 'I'
    return positions

def preparer_texte(texte):
    """Nettoie et divise le texte en paires pour le chiffrement."""
    texte = ''.join([c for c in texte.upper() if c.isalpha()]).replace('J', 'I')
    paires = []
    i = 0

    while i < len(texte):
        if i + 1 < len(texte) and texte[i] != texte[i + 1]:
            paires.append(texte[i] + texte[i + 1])
            i += 2
        else:
            paires.append(texte[i] + 'X')
            i += 1

    return paires

def chiffrer_pair(pair, tableau_cle, positions):
    """Chiffre une paire de lettres selon les règles de Playfair."""
    a, b = pair
    ligne_a, col_a = positions[a]
    ligne_b, col_b = positions[b]

    if ligne_a == ligne_b:  # Même ligne → Décalage à droite
        return tableau_cle[ligne_a][(col_a + 1) % 5] + tableau_cle[ligne_b][(col_b + 1) % 5]
    elif col_a == col_b:  # Même colonne → Décalage en bas
        return tableau_cle[(ligne_a + 1) % 5][col_a] + tableau_cle[(ligne_b + 1) % 5][col_b]
    else:  # Rectangle → Échange des colonnes
        return tableau_cle[ligne_a][col_b] + tableau_cle[ligne_b][col_a]

def dechiffrer_pair(pair, tableau_cle, positions):
    """Déchiffre une paire de lettres selon les règles de Playfair."""
    a, b = pair
    ligne_a, col_a = positions[a]
    ligne_b, col_b = positions[b]

    if ligne_a == ligne_b:  # Même ligne → Décalage à gauche
        return tableau_cle[ligne_a][(col_a - 1) % 5] + tableau_cle[ligne_b][(col_b - 1) % 5]
    elif col_a == col_b:  # Même colonne → Décalage en haut
        return tableau_cle[(ligne_a - 1) % 5][col_a] + tableau_cle[(ligne_b - 1) % 5][col_b]
    else:  # Rectangle → Échange des colonnes
        return tableau_cle[ligne_a][col_b] + tableau_cle[ligne_b][col_a]

def chiffrer_playfair(mot_clef, texte):
    """Chiffre un texte avec le chiffrement de Playfair."""
    tableau_cle = generer_tableau_cle(mot_clef)
    positions = creer_dictionnaire_positions(tableau_cle)
    paires = preparer_texte(texte)
    return ''.join(chiffrer_pair(pair, tableau_cle, positions) for pair in paires)

def dechiffrer_playfair(mot_clef, texte_chiffre):
    """Déchiffre un texte chiffré avec Playfair."""
    tableau_cle = generer_tableau_cle(mot_clef)
    positions = creer_dictionnaire_positions(tableau_cle)
    paires = [texte_chiffre[i:i+2] for i in range(0, len(texte_chiffre), 2)]
    return ''.join(dechiffrer_pair(pair, tableau_cle, positions) for pair in paires)


