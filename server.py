import select
import socket
import threading
import user_manager as UM


class ClientThread(threading.Thread):
    def __init__(self, ip, port, clientSocket) -> None:
        super(ClientThread, self).__init__()
        self.ip = ip
        self.port = port
        self.clientSocket = clientSocket
        self.username = None

    def run(self) -> None:
        self.lock = threading.Lock()
        while True:
            try:
                data = self.clientSocket.recv(1024).decode().split()
                if len(data) == 0:
                    pass
                elif data[0] == "signup":
                    # verify username and create account , username in data[1] and password in data[2]
                    # if username exists return message "username-exist" otherwise create account and return message "signup-success"
                    result = UM.createAccount(data[1], data[2])
                    self.clientSocket.send(result.encode())
                elif data[0] == "login":
                    # Message: LOGIN <username> <password>
                    result = UM.loginUser(data[1], data[2], self.ip)
                    if result in {
                        "login-account-not-exist",
                        "login-wrong-credentials",
                    }:
                        self.clientSocket.send(result.encode())
                    elif result == "login-success":
                        self.username = data[1]
                        self.lock.acquire()
                        try:
                            tcpThreads[self.username] = self
                        finally:
                            self.lock.release()

                        self.clientSocket.send(result.encode())
                        print(f"User : {self.ip} is logged in successfully")
                elif data[0] == "logout":
                    # Message: LOGOUT <username>
                    UM.logoutUser(self.username)
                    self.lock.acquire()
                    try:
                        del tcpThreads[self.username]
                    finally:
                        self.lock.release()
                    print(self.ip + ":" + str(self.port) + " is logged out")
                    self.clientSocket.close()
                    break
            except OSError as oErr:
                print("OSError: {0}".format(oErr))
            except Exception as e:
                print("Exception: {0}".format(e))
                break


TCPport = 5050
UDPport = 1515
host_ip = socket.gethostbyname(socket.gethostname())

print("Server host IP = " + host_ip)
print("Server port = " + str(TCPport))


tcpThreads = {}
# socket.AF_INET: Specifies the address family (IPv4).
# socket.SOCK_STREAM: Specifies the socket type (TCP).
# socket.SOCK_DGRAM: Datagram-oriented socket (UDP).
try:
    tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("Socket successfully created")
except socket.error as err:
    print(f"socket creation failed with error {err}")
try:
    tcpSocket.bind((host_ip, TCPport))
    udpSocket.bind((host_ip, UDPport))
except socket.error as e:
    print(f"Error binding the server socket: {e}")

tcpSocket.listen(5)  # max 5 connections in queue

sockets = [tcpSocket, udpSocket]

while sockets:
    if not sockets:
        continue
    readable, writable, exceptional = select.select(sockets, [], [])
    for sock in readable:
        if sock is tcpSocket:
            client_socket, client_address = tcpSocket.accept()
            # new thread
            print("client_address: " + str(client_address))
            newClientThread = ClientThread(client_address[0], client_address[1], client_socket)
            newClientThread.start()
