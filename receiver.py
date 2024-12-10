import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

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