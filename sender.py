import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

send_port = 4322
client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)






def startConversation():
    key = RSA.generate(1024) # Generate a private_key of 1024 bits
    priv_key = key
    public_key = key.public_key()


    client_sock.connect(("localhost", send_port))
    client_sock.send(public_key.export_key())

    cipher_rsa = PKCS1_OAEP.new(priv_key)
    received_cipher = client_sock.recv(2048)
    print(cipher_rsa.decrypt(received_cipher).decode())
    #wait for receiver's confrmation





print("Hello Mr, Do you want to start conversation(y/n): ")
choice = input()
if(choice == 'y'):
    startConversation()
    