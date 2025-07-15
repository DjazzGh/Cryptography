# Cryptography Project

## Overview

This project is a comprehensive suite of cryptographic algorithms and protocols implemented in Python. It covers classical, symmetric, and asymmetric cryptography, as well as hashing, digital signatures, and cryptographic protocols. The project features a graphical user interface (GUI) built with Tkinter, allowing users to experiment with and learn about various cryptographic techniques.

## Table of Contents
- [Project Structure](#project-structure)
- [How to Run](#how-to-run)
- [Features and Algorithms](#features-and-algorithms)
  - [Classical Ciphers](#classical-ciphers)
  - [Symmetric Ciphers](#symmetric-ciphers)
  - [Asymmetric Cryptography](#asymmetric-cryptography)
  - [Hash Functions](#hash-functions)
  - [Digital Signatures](#digital-signatures)
  - [Protocols](#protocols)
- [File Descriptions](#file-descriptions)
- [License](#license)

## Project Structure

```
Cryptography/
  main.py
  AES.py
  Affine.py
  analyse_frequentielle.py
  Cesar.py
  DES.py
  Diffie_Hellman.py
  Elgamal.py
  Fonctions_Hachage.py
  Hill_cipher.py
  Homomorphe_Elgamal.py
  IC.py
  Identification_Feige_Fiat_Shamir.py
  Identification_Schnorr.py
  otp.py
  playfair.py
  RC4.py
  RSA.py
  Shamir.py
  Signature_Elgamal.py
  Signature_RSA.py
  Standard_DSA.py
  substitution_aleatoire.py
  test_de_kasiski.py
  Vigenere.py
```

## How to Run

1. **Requirements:**
   - Python 3.x
   - Tkinter (usually included with Python)

2. **Run the Application:**
   ```bash
   python main.py
   ```
   This will launch the GUI, where you can select and experiment with different cryptographic algorithms.

## Features and Algorithms

### Classical Ciphers
- **Cesar.py**: Caesar cipher (shift cipher) for simple letter shifting.
- **Vigenere.py**: Vigenère cipher for polyalphabetic substitution.
- **Affine.py**: Affine cipher using linear transformation.
- **Hill_cipher.py**: Hill cipher using matrix multiplication.
- **playfair.py**: Playfair cipher using digraph substitution.
- **substitution_aleatoire.py**: Random monoalphabetic substitution cipher.
- **otp.py**: One-Time Pad cipher for perfect secrecy.
- **IC.py**: Index of Coincidence calculation for cryptanalysis.
- **analyse_frequentielle.py**: Frequency analysis for breaking substitution ciphers.
- **test_de_kasiski.py**: Kasiski examination for Vigenère cipher cryptanalysis.

### Symmetric Ciphers
- **AES.py**: Advanced Encryption Standard (AES) block cipher implementation.
- **DES.py**: Data Encryption Standard (DES) block cipher implementation.
- **RC4.py**: RC4 stream cipher implementation.

### Asymmetric Cryptography
- **RSA.py**: RSA encryption and decryption.
- **Elgamal.py**: ElGamal encryption and decryption.
- **Homomorphe_Elgamal.py**: Homomorphic ElGamal encryption (supports multiplicative homomorphism).
- **Diffie_Hellman.py**: Diffie-Hellman key exchange protocol.
- **Shamir.py**: Shamir's Secret Sharing scheme.

### Hash Functions
- **Fonctions_Hachage.py**: Implements MD5, SHA-1, and SHA-256 hash functions.

### Digital Signatures
- **Signature_RSA.py**: RSA digital signature scheme.
- **Signature_Elgamal.py**: ElGamal digital signature scheme.
- **Standard_DSA.py**: Digital Signature Algorithm (DSA) implementation.

### Protocols
- **Identification_Feige_Fiat_Shamir.py**: Feige-Fiat-Shamir identification protocol.
- **Identification_Schnorr.py**: Schnorr identification protocol.

## File Descriptions

### main.py
- The main entry point. Launches a Tkinter GUI for interactive cryptography demonstrations. Users can select algorithms, input text/keys, and see results.

### Classical Ciphers
- **Cesar.py**: Functions for encrypting and decrypting using the Caesar cipher.
- **Vigenere.py**: Functions for encrypting and decrypting using the Vigenère cipher.
- **Affine.py**: Functions for encrypting and decrypting using the Affine cipher. Requires keys 'a' (coprime with 26) and 'b'.
- **Hill_cipher.py**: Implements the Hill cipher (matrix-based polygraphic cipher). Includes matrix inversion and validation.
- **playfair.py**: Implements the Playfair cipher, including key table generation and digraph processing.
- **substitution_aleatoire.py**: Generates a random substitution key and provides encrypt/decrypt functions.
- **otp.py**: Implements the One-Time Pad cipher. Includes key generation, encryption, and decryption.
- **IC.py**: Calculates the Index of Coincidence for a given text.
- **analyse_frequentielle.py**: Performs frequency analysis and attempts to break substitution ciphers.
- **test_de_kasiski.py**: Implements the Kasiski test for finding key length in polyalphabetic ciphers.

### Symmetric Ciphers
- **AES.py**: Implements AES block cipher (key expansion, encryption, decryption, S-boxes, etc.).
- **DES.py**: Implements DES block cipher (initial/final permutation, Feistel structure, S-box, etc.).
- **RC4.py**: Implements the RC4 stream cipher (key scheduling and pseudo-random generation).

### Asymmetric Cryptography
- **RSA.py**: Implements RSA key generation, encryption, and decryption.
- **Elgamal.py**: Implements ElGamal key generation, encryption, and decryption.
- **Homomorphe_Elgamal.py**: Implements ElGamal with multiplicative homomorphism.
- **Diffie_Hellman.py**: Demonstrates the Diffie-Hellman key exchange protocol.
- **Shamir.py**: Implements Shamir's Secret Sharing (splitting and reconstructing secrets).

### Hash Functions
- **Fonctions_Hachage.py**: Implements MD5, SHA-1, and SHA-256 hash functions from scratch.

### Digital Signatures
- **Signature_RSA.py**: Implements RSA digital signature (signing and verification).
- **Signature_Elgamal.py**: Implements ElGamal digital signature (signing and verification).
- **Standard_DSA.py**: Implements a simplified DSA (Digital Signature Algorithm).

### Protocols
- **Identification_Feige_Fiat_Shamir.py**: Implements the Feige-Fiat-Shamir zero-knowledge identification protocol.
- **Identification_Schnorr.py**: Implements the Schnorr identification protocol.

