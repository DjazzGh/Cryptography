# Function to compute the greatest common divisor using Euclidean algorithm
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Function to find modular inverse of a number modulo m using extended Euclidean algorithm
def mod_inverse(a, m):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % m + m) % m

# Function to compute the determinant of a square matrix (supports 2x2 or 3x3)
def determinant(matrix):
    n = len(matrix)
    if n == 2:
        return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]
    elif n == 3:
        return (
            matrix[0][0] * (matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1]) -
            matrix[0][1] * (matrix[1][0] * matrix[2][2] - matrix[1][2] * matrix[2][0]) +
            matrix[0][2] * (matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0])
        )
    else:
        raise ValueError("Only 2x2 or 3x3 matrices are supported")

# Function to check if a matrix is invertible (determinant non-zero and coprime with 26)
def is_invertible(matrix):
    det = determinant(matrix)
    det = (det % 26 + 26) % 26  # Ensure positive modulo 26
    return det != 0 and gcd(det, 26) == 1

# Function to compute the adjugate (adjoint) of a matrix (supports 2x2 or 3x3)
def adjugate_matrix(matrix):
    n = len(matrix)
    if n == 2:
        return [
            [matrix[1][1], -matrix[0][1]],
            [-matrix[1][0], matrix[0][0]]
        ]
    elif n == 3:
        adj = [[0] * 3 for _ in range(3)]
        adj[0][0] = matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1]
        adj[0][1] = -(matrix[1][0] * matrix[2][2] - matrix[1][2] * matrix[2][0])
        adj[0][2] = matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0]
        adj[1][0] = -(matrix[0][1] * matrix[2][2] - matrix[0][2] * matrix[2][1])
        adj[1][1] = matrix[0][0] * matrix[2][2] - matrix[0][2] * matrix[2][0]
        adj[1][2] = -(matrix[0][0] * matrix[2][1] - matrix[0][1] * matrix[2][0])
        adj[2][0] = matrix[0][1] * matrix[1][2] - matrix[0][2] * matrix[1][1]
        adj[2][1] = -(matrix[0][0] * matrix[1][2] - matrix[0][2] * matrix[1][0])
        adj[2][2] = matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]
        return adj
    else:
        raise ValueError("Only 2x2 or 3x3 matrices are supported")

# Function to compute matrix multiplication
def matrix_multiply(matrix, vector, mod=None):
    n = len(matrix)
    result = [0] * n
    for i in range(n):
        for j in range(len(vector)):
            result[i] += matrix[i][j] * vector[j]
        if mod:
            result[i] = (result[i] % mod + mod) % mod
    return result

# Function to compute the modular inverse of a matrix modulo 26
def mod_inverse_matrix(matrix):
    det = determinant(matrix)
    det = (det % 26 + 26) % 26  # Ensure positive modulo 26
    det_inv = mod_inverse(det, 26)  # Modular inverse of determinant
    adj = adjugate_matrix(matrix)
    n = len(matrix)
    result = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            result[i][j] = (adj[i][j] * det_inv) % 26
            result[i][j] = (result[i][j] % 26 + 26) % 26  # Ensure positive
    return result

# Encryption function
def encrypt_hill(plaintext, key_matrix):
    # Remove non-alphabetic characters and convert to uppercase
    plaintext = ''.join(filter(str.isalpha, plaintext)).upper()
    n = len(key_matrix)
    padding_length = (n - len(plaintext) % n) % n
    plaintext += 'X' * padding_length  # Pad with 'X' if necessary

    # Convert plaintext to numerical vectors
    numerical_vectors = [
        [ord(char) - ord('A') for char in plaintext[i:i + n]]
        for i in range(0, len(plaintext), n)
    ]

    # Encrypt each vector
    ciphertext = ''
    for vector in numerical_vectors:
        encrypted_vector = matrix_multiply(key_matrix, vector, mod=26)
        ciphertext += ''.join([chr(num + ord('A')) for num in encrypted_vector])

    return ciphertext

# Decryption function
def decrypt_hill(ciphertext, key_matrix):
    # Remove non-alphabetic characters and convert to uppercase
    ciphertext = ''.join(filter(str.isalpha, ciphertext)).upper()
    n = len(key_matrix)

    # Convert ciphertext to numerical vectors
    numerical_vectors = [
        [ord(char) - ord('A') for char in ciphertext[i:i + n]]
        for i in range(0, len(ciphertext), n)
    ]

    # Compute inverse matrix
    inverse_matrix = mod_inverse_matrix(key_matrix)

    # Decrypt each vector
    plaintext = ''
    for vector in numerical_vectors:
        decrypted_vector = matrix_multiply(inverse_matrix, vector, mod=26)
        plaintext += ''.join([chr(int(num) + ord('A')) for num in decrypted_vector])

    return plaintext

# Example usage
if __name__ == "__main__":
    # Example key matrix (2x2)
    key_matrix = [
        [6, 24],
        [1, 16]
    ]

    # Check if the matrix is invertible
    if is_invertible(key_matrix):
        # Example plaintext
        plaintext = "HELLO"
        print(f"Original plaintext: {plaintext}")

        # Encrypt
        ciphertext = encrypt_hill(plaintext, key_matrix)
        print(f"Ciphertext: {ciphertext}")

        # Decrypt
        decrypted_text = decrypt_hill(ciphertext, key_matrix)
        print(f"Decrypted text: {decrypted_text}")
    else:
        print("Key matrix is not invertible modulo 26")