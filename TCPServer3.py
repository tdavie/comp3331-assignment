"""
    Sample code for Multi-Threaded Server
    Python 3
    Usage: python3 TCPserver3.py localhost 12000
    coding: utf-8
    
    Author: Wei Song (Tutor for COMP3331/9331)
"""
from socket import *
from threading import Thread
import sys, select

# acquire server host and port from command line parameter
if len(sys.argv) != 2:
    print("\n===== Error usage, python3 TCPServer3.py SERVER_PORT ======\n")
    exit(0)
serverHost = "127.0.0.1"
serverPort = int(sys.argv[1])
serverAddress = (serverHost, serverPort)

# define socket for the server side and bind address
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind(serverAddress)

# open credentials.txt
credentials = {}
with open("credentials.txt") as f:
    for line in f:
        tup = line.rsplit(" ")
        credentials[tup[0]] = tup[1][:-1]

print(credentials)

"""
    Define multi-thread class for client
    This class would be used to define the instance for each connection from each client
    For example, client-1 makes a connection request to the server, the server will call
    class (ClientThread) to define a thread for client-1, and when client-2 make a connection
    request to the server, the server will call class (ClientThread) again and create a thread
    for client-2. Each client will be runing in a separate therad, which is the multi-threading
"""
class ClientThread(Thread):
    def __init__(self, clientAddress, clientSocket):
        Thread.__init__(self)
        self.clientAddress = clientAddress
        self.clientSocket = clientSocket
        self.clientAlive = False
        
        print("===== New connection created for: ", clientAddress)
        self.clientAlive = True
        
    def run(self):
        message = ''
        
        while self.clientAlive:
            # use recv() to receive message from the client
            data = self.clientSocket.recv(1024)
            message = data.decode()
            print(message)
            
            # if the message from client is empty, the client would be off-line then set the client as offline (alive=Flase)
            if message == '':
                self.clientAlive = False
                print("===== the user disconnected - ", clientAddress)
                break

            # parse requests
            parsed_message = self.parse_request(message)
            
            # switch based on request method
            if parsed_message["method"] == "AUT":
                print("[recv] New login request")
                if self.process_login(parsed_message):
                    # todo what is the appropriate response to send to a successfully authenticated client? 
                    response = "generic welcome message"
                    self.clientSocket.send(response.encode())
                else:
                    # todo what is the appropriate response to send to a unsuccessful client? 
                    response = "generic failure message"
                    self.clientSocket.send(response.encode())

            # elif message == 'download':
            #     print("[recv] Download request")
            #     message = 'download filename'
            #     print("[send] " + message)
            #     self.clientSocket.send(message.encode())
            # else:
            #     print("[recv] " + message)
            #     print("[send] Cannot understand this message")
            #     message = 'Cannot understand this message'
            #     self.clientSocket.send(message.encode())
    
    """
        You can create more customized APIs here, e.g., logic for processing user authentication
        Each api can be used to handle one specific function, for example:
        def process_login(self):
            message = 'user credentials request'
            self.clientSocket.send(message.encode())
    """
    def process_login(message):
        # verify credentials
        if message["arguments"][0] in credentials:
            if message["arguments"][1] == credentials[message["arguments"][0]]:
                print('[send] ' + message)
                return True
        return False

    '''
    parses bare requests, separating the method and any content, delineated by whitespace
    '''
    def parse_request(rq):
        return {"method": rq[:3], "arguments": rq.rsplit(" ")}
        



print("\n===== Server is running =====")
print("===== Waiting for connection request from clients...=====")


while True:
    serverSocket.listen()
    clientSockt, clientAddress = serverSocket.accept()
    clientThread = ClientThread(clientAddress, clientSockt)
    clientThread.start()
