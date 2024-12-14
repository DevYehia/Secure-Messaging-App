import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from sympy import mod_inverse, isprime
from random import randint
import base64


send_port = 4322
client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

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
def rsa_sign(private_key, message):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    signature = cipher.encrypt(message.encode())  # Convert message to bytes
    return signature




# # RSA Key Generation
# rsa_key = RSA.generate(2048)
# rsa_public_key = rsa_key.publickey()

# # AES Key Generation
# aes_key = get_random_bytes(16)

# # ElGamal Key Generation
# elgamal_public_key, elgamal_private_key = elgamal_keygen()

# # Encrypt AES Key with ElGamal
# plaintext_aes_key = int.from_bytes(aes_key, 'big')
# elgamal_encrypted_key = elgamal_encrypt(elgamal_public_key, plaintext_aes_key)

# # Sign ElGamal Encrypted AES Key with RSA
# hashed = SHA256.new(repr(elgamal_encrypted_key).encode())
# signature = pkcs1_15.new(rsa_key).sign(hashed)

# # Encrypt Message with AES
# message = "Hello Friend I'm tired"
# aes_encrypted_message = aes_encrypt(aes_key, message)

# # Transmit elgamal_encrypted_key, signature, and encrypted message
# with open('transmission.txt', 'w') as f:
#     f.write(f"{elgamal_encrypted_key}\n{signature.hex()}\n{aes_encrypted_message}\n")
# with open('public_key.pem', 'wb') as f:
#     f.write(rsa_public_key.export_key())




# def startConversation():
#     key = RSA.generate(1024) # Generate a private_key of 1024 bits
#     priv_key = key
#     public_key = key.public_key()


#     client_sock.connect(("localhost", send_port))
#     client_sock.send(public_key.export_key())

#     cipher_rsa = PKCS1_OAEP.new(priv_key)
#     received_cipher = client_sock.recv(2048)
#     print(cipher_rsa.decrypt(received_cipher).decode())
#     #wait for receiver's confrmation





# print("Hello Mr, Do you want to start conversation(y/n): ")
# choice = input()
# if(choice == 'y'):
#     startConversation()
    
    
    
