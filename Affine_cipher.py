# affine
import math

def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None  

#  Encryption: C = (a *p + b) % 26
def encrypt_affine(a, b, plain_text):
    if math.gcd(a, 26) != 1:  
        raise ValueError("Key 'a' must be coprime with 26.")

    cipher_text = ""
    for char in plain_text:
        if char.isalpha(): 
            if char.islower():
                new_char = chr(((a * (ord(char) - ord('a')) + b) % 26) + ord('a'))
            elif char.isupper():
                new_char = chr(((a * (ord(char) - ord('A')) + b) % 26) + ord('A'))
            cipher_text += new_char
        else:
            cipher_text += char  
    return cipher_text

# Decryption: P = a^(-1) * (C - b) % 26
def decrypt_affine(a, b, cipher_text):
    a_inv = mod_inverse(a, 26) 
    if a_inv is None:
        raise ValueError("Key 'a' has no modular inverse. Choose another 'a'.")

    plain_text = ""
    for char in cipher_text:
        if char.isalpha():  
            if char.islower():
                new_char = chr(((a_inv * (ord(char) - ord('a') - b)) % 26) + ord('a'))
            elif char.isupper():
                new_char = chr(((a_inv * (ord(char) - ord('A') - b)) % 26) + ord('A'))
            plain_text += new_char
        else:
            plain_text += char  
    return plain_text
