"""
This module provides functions required for the sender to securely send a message.

Functions:
elgamal_keygen() : Generate ElGamal Keys.
elgamal_decrypt() : Decrypt a ciphertext that was encrypted using elgamal public key.
aes_encrypt() : Encrypt text using an AES key.
generate_rsa_keys() : Generate RSA keys.
rsa_sign() : Makes SHA256 hash of the message bytes then signs the hashed message using the private RSA key.
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from sympy import mod_inverse, isprime
from random import randint
import base64

# ElGamal Key Generation
def elgamal_keygen(bit_length=256):
    # Generate a large prime p
    p = 0
    while not isprime(p):  # Ensure p is prime
        p = randint(2**(bit_length - 1), 2**bit_length - 1)
    
    g = randint(2, p - 1)  # Random generator
    x = randint(1, p - 2)  # Private key
    y = pow(g, x, p)       # Public key
    return (p, g, y), x    # Return public key (p, g, y) and private key x

# ElGamal Decryption
def elgamal_decrypt(private_key, public_key, ciphertext):
    p, _, _ = public_key
    c1, c2 = ciphertext
    s = pow(c1, private_key, p)  # c1^x mod p
    s_inv = mod_inverse(s, p)
    plaintext = (c2 * s_inv) % p  # m = c2 * (s^-1 mod p) mod p
    return plaintext

# AES Encryption
def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()


# RSA Key Pair Generation
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# RSA Sign (Encrypt with Private Key)
def rsa_sign(private_key, message_bytes):
    rsa_key = RSA.import_key(private_key)
    message_hash = SHA256.new(message_bytes)
    signature = pkcs1_15.new(rsa_key).sign(message_hash)
    return signature
