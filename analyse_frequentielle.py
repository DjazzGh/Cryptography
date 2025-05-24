from collections import Counter
import string


# Fréquences moyennes des lettres en français et en anglais
FREQ_FR = {'E': 14.7, 'A': 8.4, 'S': 7.9, 'I': 7.5, 'T': 7.2, 'N': 7.0, 'R': 6.5, 'U': 6.2, 'L': 5.5, 'O': 5.1, 'D': 3.6, 'C': 3.3, 'M': 3.2, 'P': 3.1, 'G': 1.2, 'B': 1.1, 'V': 1.0, 'H': 0.9, 'F': 0.9, 'Q': 0.6, 'Y': 0.4, 'X': 0.4, 'J': 0.3, 'K': 0.2, 'W': 0.1, 'Z': 0.1}
FREQ_EN = {'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 6.9, 'N': 6.7, 'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8, 'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.5, 'V': 1.0, 'K': 0.8, 'J': 0.2, 'X': 0.2, 'Q': 0.1, 'Z': 0.1}


def normalize_frequencies(text):
    text = text.upper()
    letter_counts = Counter(c for c in text if c in string.ascii_uppercase)
    total = sum(letter_counts.values())
    frequencies = {letter: (count / total) * 100 for letter, count in letter_counts.items()}
    return frequencies


def compare_frequencies(cipher_freq, lang_freq):
    sorted_cipher = sorted(cipher_freq.items(), key=lambda x: x[1], reverse=True)
    sorted_lang = sorted(lang_freq.items(), key=lambda x: x[1], reverse=True)
    mapping = {sorted_cipher[i][0]: sorted_lang[i][0] for i in range(len(sorted_cipher))}
    return mapping


def decipher_substitution(ciphertext, mapping):
    return "".join(mapping.get(c, c) for c in ciphertext.upper())


# Exemple de texte chiffré
ciphertext = "WZMDQ ZMDQS VQMDQ"

# Étape 1: Analyser les fréquences
cipher_freq = normalize_frequencies(ciphertext)
print("Fréquences des lettres dans le texte chiffré:", cipher_freq)

# Étape 2: Comparer avec le français et l'anglais
mapping_fr = compare_frequencies(cipher_freq, FREQ_FR)
mapping_en = compare_frequencies(cipher_freq, FREQ_EN)
print("Mapping probable (FR):", mapping_fr)
print("Mapping probable (EN):", mapping_en)

# Étape 3: Déchiffrer (tentative en français)
plaintext_fr = decipher_substitution(ciphertext, mapping_fr)
print("Texte probable en français:", plaintext_fr)

# Étape 4: Déchiffrer (tentative en anglais)
plaintext_en = decipher_substitution(ciphertext, mapping_en)
print("Texte probable en anglais:", plaintext_en)



from collections import Counter
import string

def frequency_analysis(text):
    """Analyse la fréquence des lettres dans un texte."""
    # On filtre les lettres et convertit en majuscules
    text = ''.join(filter(str.isalpha, text)).upper()

    # Compter les occurrences des lettres
    letter_counts = Counter(text)
    
    # Calculer la fréquence relative
    total_letters = sum(letter_counts.values())
    frequencies = {letter: round(count / total_letters * 100, 2) for letter, count in letter_counts.items()}
    
    # Trier par fréquence décroissante
    sorted_frequencies = dict(sorted(frequencies.items(), key=lambda x: x[1], reverse=True))
    
    return sorted_frequencies

