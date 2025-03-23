import numpy as np

# function to check if a matrix is invertible
def is_invertible(matrix):
    det = int(np.round(np.linalg.det(matrix)))  # Calculate determinant
    return det != 0 and np.gcd(det, 26) == 1  # Check if determinant is non-zero and coprime with 26

#  function to generate the inverse of a matrix modulo 26
def mod_inverse_matrix(matrix):
    det = int(np.round(np.linalg.det(matrix)))  # Determinant of the matrix
    det_inv = pow(det, -1, 26)  # Modular inverse of the determinant
    matrix_modulus_inv = (
        det_inv * np.round(det * np.linalg.inv(matrix)).astype(int) % 26
    )  
    return matrix_modulus_inv

# Encryption
def encrypt_hill(plaintext, key_matrix):
    # Remove non-alphabetic characters and convert to uppercase
    plaintext = ''.join(filter(str.isalpha, plaintext)).upper()
    n = len(key_matrix)  
    padding_length = (n - len(plaintext) % n) % n 
    plaintext += 'X' * padding_length  # Pad with 'X' if necessary

    # Convert plaintext to numerical vectors
    numerical_vectors = [
        [ord(char) - ord('A') for char in plaintext[i : i + n]]
        for i in range(0, len(plaintext), n)
    ]

    # Encrypt each vector
    ciphertext = ''
    for vector in numerical_vectors:
        encrypted_vector = np.dot(key_matrix, vector) % 26  
        ciphertext += ''.join([chr(num + ord('A')) for num in encrypted_vector])

    return ciphertext

# Decryption
def decrypt_hill(ciphertext, key_matrix):
    # Remove non-alphabetic characters and convert to uppercase
    ciphertext = ''.join(filter(str.isalpha, ciphertext)).upper()
    n = len(key_matrix)  # Size of the key matrix

    # Convert ciphertext to numerical vectors
    numerical_vectors = [
        [ord(char) - ord('A') for char in ciphertext[i : i + n]]
        for i in range(0, len(ciphertext), n)
    ]

    
    inverse_matrix = mod_inverse_matrix(key_matrix)

    # Decrypt each vector
    plaintext = ''
    for vector in numerical_vectors:
        decrypted_vector = np.dot(inverse_matrix, vector) % 26  
        plaintext += ''.join([chr(int(num) + ord('A')) for num in decrypted_vector])

    return plaintext
