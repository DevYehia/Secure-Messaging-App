"""
This module provides functions required for the receiver to securely receive a message.

Functions:
elgamal_encrypt() : Encrypt text using elgamal public key.
aes_decrypt() : Decrypt ciphertext using AES key.
gen_aes_key() : Generate AES key.
rsa_verify() : Hash message bytes then verify the signed message with hash using RSA public key.
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from random import randint
import base64



# ElGamal Encryption
def elgamal_encrypt(public_key, plaintext):
    p, g, y = public_key
    if plaintext >= p:
        raise ValueError("Plaintext must be smaller than the prime p.")
    
    k = randint(1, p - 2)    # Random ephemeral key
    c1 = pow(g, k, p)        # c1 = g^k mod p
    c2 = (plaintext * pow(y, k, p)) % p  # c2 = m * y^k mod p
    return c1, c2

# AES Decryption
def aes_decrypt(key, ciphertext):
    data = base64.b64decode(ciphertext)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def gen_aes_key():
    return get_random_bytes(16)

# RSA Verify (Decrypt with Public Key)
def rsa_verify(public_key, message_bytes, signature):
    rsa_key = RSA.import_key(public_key)
    message_hash = SHA256.new(message_bytes)
    try:
        pkcs1_15.new(rsa_key).verify(message_hash, signature)
        return True
    except (ValueError, TypeError):
        return False
