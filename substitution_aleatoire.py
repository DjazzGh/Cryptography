import random

def generate_key():
    
    #Generate a random substitution key 
    alphabet = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    shuffled_alphabet = alphabet.copy()
    random.shuffle(shuffled_alphabet)
    return dict(zip(alphabet, shuffled_alphabet))

def encrypt(plaintext, key):
    ciphertext = []
    for char in plaintext.upper():
        if char in key:
            ciphertext.append(key[char])
        else:
            ciphertext.append(char) 
    return ''.join(ciphertext)

def decrypt(ciphertext, key):
    reverse_key = {v: k for k, v in key.items()}  # Create inverse mapping
    plaintext = []
    for char in ciphertext.upper():
        if char in reverse_key:
            plaintext.append(reverse_key[char])
        else:
            plaintext.append(char)  
    return ''.join(plaintext)