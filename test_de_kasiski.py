import re
from collections import Counter
from itertools import cycle
#import numpy as np

def find_repeated_sequences(ciphertext, min_length=3):
    sequences = {}
    for i in range(len(ciphertext) - min_length + 1):
        seq = ciphertext[i:i+min_length]
        matches = [m.start() for m in re.finditer(seq, ciphertext)]
        if len(matches) > 1:
            sequences[seq] = matches
    return sequences

def find_key_length(ciphertext):
    sequences = find_repeated_sequences(ciphertext)
    distances = []
    for seq, positions in sequences.items():
        for i in range(len(positions) - 1):
            distances.append(positions[i+1] - positions[i])
    
    if not distances:
        return None
    
    factors = Counter()
    for d in distances:
        for i in range(2, d + 1):
            if d % i == 0:
                factors[i] += 1
    
    probable_length = factors.most_common(1)
    return probable_length[0][0] if probable_length else None

def decrypt_vigenere(ciphertext, key):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key_sequence = cycle(key)
    plaintext = ""
    
    for letter in ciphertext:
        if letter in alphabet:
            shift = alphabet.index(next(key_sequence))
            new_index = (alphabet.index(letter) - shift) % len(alphabet)
            plaintext += alphabet[new_index]
        else:
            plaintext += letter
    return plaintext

def frequency_analysis(subtext):
    letter_freq = Counter(subtext)
    most_common = letter_freq.most_common(1)[0][0]
    return most_common

def find_key(ciphertext, key_length):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key = ""
    
    for i in range(key_length):
        subtext = ciphertext[i::key_length]
        most_common_letter = frequency_analysis(subtext)
        shift = (alphabet.index(most_common_letter) - alphabet.index('E')) % 26
        key += alphabet[shift]
    
    return key
