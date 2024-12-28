import base64
import socket
import sender
import receiver

SERVER_TCP_PORT = 5050


class Peer:
    """
    This class provides a CLI for the user to securely send or receive a message.
    """
    def __init__(self):
        self.server_ip = input("Enter Server IP: ")
        self.server_port = SERVER_TCP_PORT
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.connect((self.server_ip.strip(), self.server_port))
        self.username = None
        (self.sender_elgamal_public_p,self.sender_elgamal_public_g,self.sender_elgamal_public_y), self.sender_elgamal_private = (None, None, None), None
        self.sender_RSA_public, self.sender_RSA_private = None, None
        self.receiver_aes_key = None
        try:
            option = 0
            while option != "5":
                print(f""" Choose one of the following options:
                1- Login
                2- Signup
                3- Send a message
                4- Receive a message
                5. Exit"""
                )
                option = input("Enter your option: ")
                if option == "1":
                    username = input("Enter username: ")
                    password = input("Enter password: ")
                    self.login(username, password)
                elif option == "2":
                    username = input("Enter username: ")
                    password = input("Enter password: ")
                    while len(password) < 6:
                        print("Password must be 6 characters long!")
                        password = input("Enter password: ")
                    self.createAccount(username, password)
                elif option == "3":
                    if self.username != None:
                        msg = input("Enter message: ")
                        self.send_message(msg)
                    else :
                        print("Login or Signup First!")
                elif option == "4" :
                    if self.username != None:
                        received_msg = self.receive_message()
                        print(f'Received message: {received_msg}')
                    else :
                        print("Login or Signup First!")
                elif int(option) > 5 :
                    print("Invalid Input")
            if option == "5":
                self.exitApp()
                
        except Exception as e:
                    print(f"An error occurred option: {e}")

    def createAccount(self, username, password):
        message = "signup " + username + " " + password
        self.tcp_socket.send(message.encode())
        response = self.tcp_socket.recv(1024).decode()
        if response == "username-exist":
            print(f'Signup failed username {username} already exist')
        elif response == "signup-success":
            print(f'Signed up username {username}')

    def exitApp(self):
        if self.username != None:
            self.tcp_socket.close()
            self.udp_socket.close()
            print("Exited")
        else:
            self.tcp_socket.close()
            self.udp_socket.close()
            print("Exited")

    def login(self, username, password):
        message = "login " + username + " " + password
        self.tcp_socket.send(message.encode())
        response = self.tcp_socket.recv(1024).decode()
        if response == "login-success":
            self.username = username
            (self.sender_elgamal_public_p, self.sender_elgamal_public_g, self.sender_elgamal_public_y), self.sender_elgamal_private = sender.elgamal_keygen()
            print(f"""Generated elgamal keys:
                  elgamal_public_p: {self.sender_elgamal_public_p}
                  elgamal_public_g: {self.sender_elgamal_public_g}
                  elgamal_public_y: {self.sender_elgamal_public_y}
                  elgamal_private: {self.sender_elgamal_private}
                  """)
            self.sender_RSA_private, self.sender_RSA_public  = sender.generate_rsa_keys()
            print(f"""Generated RSA keys:
                  RSA_public: {self.sender_RSA_public}
                  RSA_private: {self.sender_RSA_private}
                  """)
            self.receiver_aes_key = receiver.gen_aes_key();
            print(f"""Generated AES key:
                  aes_key: {self.receiver_aes_key}
                  """)
            print(f'User {username} loggedin')
        elif response == "login-account-not-exist":
            print(f'Login for user {username} failed, signup first')
        elif response == "login-wrong-credentials":
            print("Invalid username or password")

    def send_message(self, message):
        try:
            if self.username != None :
                try:
                    # Create a TCP socket
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                        # Connect to the server
                        receiver_ip = input("Enter receiver ip address: ")
                        receiver_port = input("Enter receiver port number: ")
                        receiver_address = (receiver_ip.strip(),int(receiver_port))
                        client_socket.connect(receiver_address)
                        print(f"Connected to {receiver_address}")
                        # send elgamal public key and RSA public key
                        sender_publish_keys_message = f'{self.sender_elgamal_public_p}\x1F{self.sender_elgamal_public_g}\x1F{self.sender_elgamal_public_y}\x1F{self.bytes_to_string(self.sender_RSA_public)}'
                        client_socket.sendall(sender_publish_keys_message.encode())
                        # wait for receiver's AES key encrypted with elgamal public key
                        receiver_aes_encrypted_message = client_socket.recv(4096).decode().split('\x1F')
                        receiver_aes_encrypted = (int(receiver_aes_encrypted_message[0]),int(receiver_aes_encrypted_message[1]))
                        # decrypt receiver's AES key using elgamal
                        receiver_aes_decrypted_at_sender = sender.elgamal_decrypt(self.sender_elgamal_private,(self.sender_elgamal_public_p,self.sender_elgamal_public_g,self.sender_elgamal_public_y),receiver_aes_encrypted)
                        receiver_aes_decrypted_at_sender_bytes = receiver_aes_decrypted_at_sender.to_bytes(length=16,byteorder='big')
                        # encrypt message with receiver's AES key
                        sender_AES_encrypted_message = sender.aes_encrypt(receiver_aes_decrypted_at_sender_bytes,message)
                        sender_message_bytes = message.encode()
                        # hash and sign the message bytes
                        sender_message_bytes_SHA256_hashed_RSA_signed = sender.rsa_sign(self.sender_RSA_private,sender_message_bytes)
                        sender_message_encrypted_and_hashed = f'{sender_AES_encrypted_message}\x1F{self.bytes_to_string(sender_message_bytes_SHA256_hashed_RSA_signed)}'
                        # send AES encrypted message and message signature
                        client_socket.sendall(sender_message_encrypted_and_hashed.encode())
                        
                except ConnectionRefusedError:
                    print("Connection refused. Make sure the server is running.")
                except Exception as e:
                    print(f"An error occurred: {e}")
                
                
            else :
                print("Not loggedin!")
        except Exception as e:
            print("Exception: {0}".format(e))
            

    def bytes_to_string(self,s_bytes):
        """
        Convert bytes to a Base64-encoded string.
        
        Args:
            s_bytes (bytes): The bytes to encode.
        
        Returns:
            str: The Base64-encoded string representation of the bytes.
        """
        return base64.b64encode(s_bytes).decode('utf-8')

    def string_to_bytes(self,s_string):
        """
        Convert a Base64-encoded string back to the original bytes.
        
        Args:
            s_string (str): The Base64-encoded string representation of the bytes.
        
        Returns:
            bytes: The original bytes.
        """
        return base64.b64decode(s_string)

    def receive_message(self):
        if self.username != None :
            try:
                # Create a TCP socket
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                    # Bind the socket to the address and port
                    server_socket.bind((socket.gethostbyname(socket.gethostname()), 5000))
                    print(f"Server listening on {(socket.gethostbyname(socket.gethostname()), 5000)}")
                    
                    # Listen for incoming connections
                    server_socket.listen(1)
                    
                    # Accept a connection
                    conn, sender_address = server_socket.accept()
                    with conn:
                        print(f"Connected by {sender_address}")
                        # wait for ssender's elgamal public key and RSA public key
                        data = conn.recv(4096)
                        if data:
                            sender_elgamal_public_p,sender_elgamal_public_g,sender_elgamal_public_y,sender_RSA_public = data.decode().split('\x1F')
                            # encrypt AES key with sender's elgamal public key
                            receiver_aes_encrypted = receiver.elgamal_encrypt((int(sender_elgamal_public_p),int(sender_elgamal_public_g),int(sender_elgamal_public_y)),int.from_bytes(self.receiver_aes_key))
                            receiver_aes_encrypted_message = f'{receiver_aes_encrypted[0]}\x1F{receiver_aes_encrypted[1]}'
                            # send encrypted AES key
                            conn.sendall(receiver_aes_encrypted_message.encode())
                            # wait for sender's encrypted message and signed message
                            data = conn.recv(4096)
                            if data:
                                sender_AES_encrypted_message, sender_message_bytes_SHA256_hashed_RSA_signed = data.decode().split('\x1F')
                                # decrypt message using AES key
                                receiver_AES_decrypted_msg = receiver.aes_decrypt(self.receiver_aes_key,sender_AES_encrypted_message)
                                receiver_AES_decrypted_msg_bytes = receiver_AES_decrypted_msg.encode()
                                # Verify the integrity of the message using sender's RSA public key, decrypted message, and the signature message
                                receiver_RSA_verified_hashed_msg_bool = receiver.rsa_verify(self.string_to_bytes(sender_RSA_public),receiver_AES_decrypted_msg_bytes,self.string_to_bytes(sender_message_bytes_SHA256_hashed_RSA_signed))
                                if receiver_RSA_verified_hashed_msg_bool:
                                    return receiver_AES_decrypted_msg
                            else:
                                print("No data received 2")
                            
                        else:
                            print("No data received 1")
                            
            except Exception as e:
                print(f"An error occurred: {e}")
        else:
            print("Not loggedin!")
            
        



Peer()
