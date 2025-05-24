import itertools

# Permutation Initiale
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Permutation Finale (Inverse of IP)
FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

# Expansion Table 
E = [32, 1, 2, 3, 4, 5, 4, 5,
     6, 7, 8, 9, 8, 9, 10, 11,
     12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21,
     22, 23, 24, 25, 24, 25, 26, 27,
     28, 29, 28, 29, 30, 31, 32, 1]

# Simple S-Box 
SBOX = [9, 14, 4, 7, 1, 0, 2, 8, 6, 11, 10, 12, 3, 5, 13, 15]

# Permutation Table for F function
P = [16, 7, 20, 21,
     29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2, 8, 24, 14,
     32, 27, 3, 9,
     19, 13, 30, 6,
     22, 11, 4, 25]

# Initial 64-bit key
KEY = "133457799BBCDFF1"

def hex_to_bin(hex_str):
    return bin(int(hex_str, 16))[2:].zfill(64)

def bin_to_hex(bin_str):
    return hex(int(bin_str, 2))[2:].upper()

def permute(block, table):
    return ''.join(block[i-1] for i in table)

def xor(a, b):
    return ''.join('0' if x == y else '1' for x, y in zip(a, b))

def sbox_substitution(block):
    """Perform a simple S-Box substitution."""
    return ''.join(bin(SBOX[int(block[i:i+4], 2)])[2:].zfill(4) for i in range(0, len(block), 4))

def generate_keys(key):
    """Generate 16 round keys."""
    return [key[i:] + key[:i] for i in range(16)]  # Simple rotation as key scheduling

def f_function(block, subkey):
    """Feistel function (E expansion -> XOR -> S-Box -> P permutation)."""
    expanded_block = permute(block, E)
    xored_block = xor(expanded_block, subkey)
    sbox_output = sbox_substitution(xored_block)
    return permute(sbox_output, P)

def des_encrypt(plaintext, key):
    """DES Encryption Process"""
    binary_plaintext = hex_to_bin(plaintext)
    binary_key = hex_to_bin(key)

    permuted_text = permute(binary_plaintext, IP)
    left, right = permuted_text[:32], permuted_text[32:]

    round_keys = generate_keys(binary_key[:48])  

    for i in range(16):
        new_right = xor(left, f_function(right, round_keys[i]))
        left, right = right, new_right

    combined = right + left  
    cipher_text = permute(combined, FP)
    return bin_to_hex(cipher_text)

def des_decrypt(ciphertext, key):
    """DES Decryption Process"""
    binary_ciphertext = hex_to_bin(ciphertext)
    binary_key = hex_to_bin(key)

    permuted_text = permute(binary_ciphertext, IP)
    left, right = permuted_text[:32], permuted_text[32:]

    round_keys = generate_keys(binary_key[:48])  
    round_keys.reverse()  # Reverse for decryption

    for i in range(16):
        new_right = xor(left, f_function(right, round_keys[i]))
        left, right = right, new_right

    combined = right + left
    plain_text = permute(combined, FP)
    return bin_to_hex(plain_text)

