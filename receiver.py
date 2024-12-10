import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from sympy import mod_inverse
import base64

# ElGamal Decryption
def elgamal_decrypt(private_key, public_key, ciphertext):
    p, _, _ = public_key
    c1, c2 = ciphertext
    s = pow(c1, private_key, p)  # c1^x mod p
    s_inv = mod_inverse(s, p)
    plaintext = (c2 * s_inv) % p  # m = c2 * (s^-1 mod p) mod p
    return plaintext

# AES Decryption
def aes_decrypt(key, ciphertext):
    data = base64.b64decode(ciphertext)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# Read transmitted data
with open('transmission.txt', 'r') as f:
    lines = f.readlines()
    elgamal_encrypted_key = eval(lines[0].strip())
    signature = bytes.fromhex(lines[1].strip())
    aes_encrypted_message = lines[2].strip()

with open('public_key.pem', 'rb') as f:
    rsa_public_key = RSA.import_key(f.read())

# Receiver Side: Verify RSA Signature
hashed_verify = SHA256.new(repr(elgamal_encrypted_key).encode())
try:
    pkcs1_15.new(rsa_public_key).verify(hashed_verify, signature)
    print("Signature is valid.")
except (ValueError, TypeError):
    print("Signature is invalid.")

# Decrypt AES Key with ElGamal
elgamal_public_key = (p, g, y)  # Replace with actual public key components
elgamal_private_key = x         # Replace with actual private key
recovered_aes_key = elgamal_decrypt(elgamal_private_key, elgamal_public_key, elgamal_encrypted_key)
recovered_aes_key_bytes = recovered_aes_key.to_bytes((recovered_aes_key.bit_length() + 7) // 8, 'big')

# Confirm Keys Match
if recovered_aes_key_bytes == aes_key:
    print("AES key recovered successfully.")
    # Decrypt Message
    decrypted_message = aes_decrypt(recovered_aes_key_bytes, aes_encrypted_message)
    print(f"Decrypted Message: {decrypted_message}")
else:
    print("Failed to recover AES key.")


recv_port = 4322
recveiver_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
def listenForConversation():
    recveiver_sock.bind(('', recv_port))
    recveiver_sock.listen(5)
    while True:
        sending_sock, addr = recveiver_sock.accept()
        raw_sender_public_key = sending_sock.recv(2048)
        sender_public_key = RSA.import_key(raw_sender_public_key)
        cipher_rsa = PKCS1_OAEP.new(sender_public_key)
        cipher_text = cipher_rsa.encrypt(b"Hello Mr")
        sending_sock.send(cipher_text)

print("Listening For Incoming Requests")
listenForConversation()