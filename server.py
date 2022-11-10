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
from datetime import datetime

MAX_LOGIN_ATTEMPTS = 3
CURRENT_MAX_ID = 0
TIMEOUT_SECONDS = 10


# acquire server host and port from command line parameter
if len(sys.argv) != 2:
    print("\n===== Error usage, python3 TCPServer3.py SERVER_PORT ======\n")
    exit(0)
serverHost = "127.0.0.1"
serverPort = int(sys.argv[1])
serverAddress = (serverHost, serverPort)

# define socket for the server side and bind address
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
serverSocket.bind(serverAddress)

# open credentials.txt
credentials = {}
with open("credentials.txt") as f:
    for line in f:
        tup = line.rsplit(" ")
        credentials[tup[0]] = tup[1].rstrip()

print(credentials)

# define global host db for auth
# used for devices which have not yet been authenticated, keeping track of previous logins etc. to enforce rate limiting etc.
unauthenticatedHosts = {
    "device-name": {
        "id": 0,
        "ip": "100.100.100.100",
        "port": "10000",
        "isAuthenticated": False,
        "lastAuthAttempt": 0,
        "authAttemptCount": 0,
    }
}
# once a device is authenticated, it is removed from unauthenticatedDevices and added to authenticatedDevices
authenticatedHosts = {
    "device-name": {
        "id": 0,
        "ip": "100.100.100.100",
        "port": "10000"
    }
}

# DB Helpers
# __________

# def get_host_index_by_IP(l, IP):
#     for x, host in enumerate(unauthenticatedHosts):
#         if host["ip"] == IP:
#             return x
#     return False

# write to device log
def log_write(log, message):
    with open(log, "w") as log:
        log.write(message)

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
            # AUT
            if parsed_message["method"] == "AUT":
                print("[recv] New login request")

                # send login request to client
                # self.clientSocket.sendall("===== Welcome, please log in =====\n".encode())

                # add edge device to hosts dict
                global CURRENT_MAX_ID
                unauthenticatedHosts[parsed_message["arguments"][1]] = {
                    "id": CURRENT_MAX_ID,
                    "ip": self.clientAddress,
                    "port": self.clientSocket,
                    "lastAuthAttempt": 0,
                    "authAttemptCount": 0,
                    }
                CURRENT_MAX_ID += 1

                # process login
                self.process_login(parsed_message)
            # EDG
            elif parsed_message["method"] == "EDG":
                print("[recv] New file upload request from ")

    """
        APIs
    """
    def process_login(self, message):
        #index = get_host_index_by_IP(unauthenticatedHosts, self.clientAddress)
        
        # unable to find host in list
        # if not index:
        #     print("unable to find host in unauthentiacted host list, this shouldn't happen...")
        #     return

        name = message["arguments"][1]
        
        # check id edge device is timed out
        if unauthenticatedHosts[name]["authAttemptCount"] > MAX_LOGIN_ATTEMPTS:
            if datetime.strptime(unauthenticatedHosts[name]["lastAuthAttempt"], '%b %d %Y %I:%M%p') + TIMEOUT_SECONDS < datetime.now():
                return
            
        # login loop
        while unauthenticatedHosts[name]["authAttemptCount"] < MAX_LOGIN_ATTEMPTS - 1:
            if self.check_credentials(message):
                # todo what is the appropriate response to send to a successfully authenticated client? 
                response = "generic welcome message"
                print('client login successful')
                self.clientSocket.send(response.encode())
               
                # update device log
                log_write("edge-device-log.txt", f"{datetime.now()}; {message['arguments'][1]}; {self.clientAddress}; {self.clientSocket}")
                
                # remove device from unauthenticated hosts
                del unauthenticatedHosts[name]

                # listen for UDP port
                data = self.clientSocket.recv(1024)
                port = int(data.decode())

                return port
            else:
                unauthenticatedHosts[name]["authAttemptCount"] += 1
                # authentication failure
                response = f"authentication failed, please try again (Attempt {unauthenticatedHosts[name]['authAttemptCount']}/{MAX_LOGIN_ATTEMPTS})"
                self.clientSocket.send(response.encode())
                
                data = self.clientSocket.recv(1024)
                message = self.parse_request(data.decode())

        # todo what is the appropriate response to send to a unsuccessful client? 
        response = "Authentication failed. You have been timed out for 10 seconds"
        self.clientSocket.send(response.encode())

        # update timeout
        unauthenticatedHosts[name]["lastAuthAttempt"] = datetime.now()
        print(unauthenticatedHosts[name]["lastAuthAttempt"])

        # remove device from unauthenticated hosts
        del unauthenticatedHosts[name]
    '''
        Edge sends file to server
    '''
    def receive_file(fileID, dataAmount):
        # send response to client, wait for tcp stream

        # receive file over TCP stream

        # acknowledge file receipt
        
        pass

    '''
        Server requests a file fromedge device, edge device send it over TCP 
    '''
    def request_file(fileID, dataAmount):
        # send request to client

        # wait for acknowledgement from client

        # wait for TCP stream

        # acknowledge file receipt
        
        pass

    
    '''
        Request server to do a computation operation (SUM, AVERAGE, MAX, MIN. SUM) on fileID
    '''
    def do_compute(fileID, computationOperation):
        # do compute

        # send response
        
        pass

    '''
        Edge device deletes a file stored on server
    '''
    def delete(fileID):
        # delete file

        # send response
        
        pass

    '''
        Edge device requests a list of all other edge devics from server
    '''
    def list_edge_devices():
        # read from active edge device list

        # send response
        
        pass

    '''
        Edge device requests to leave the network
    '''
    def remove_edge_device(deviceID):
        # remove device from datastructures

        # send response
        
        pass
    
    '''
        checks whether provided credentials match credentials.txt
    '''
    def check_credentials(self, message):
        print(f'{message["arguments"][1]}, {message["arguments"][2]}')
        if message["arguments"][1] in credentials:
            if message["arguments"][2] == credentials[message["arguments"][1]]:
                return True
        return False

    '''
    parses bare requests, separating the method and any content, delineated by whitespace
    '''
    def parse_request(self, rq):
        return {"method": rq[:3], "arguments": rq.rsplit(" ")}
        



print("\n===== Server is running =====")
print("===== Waiting for connection request from clients...=====")


while True:
    serverSocket.listen()
    clientSockt, clientAddress = serverSocket.accept()
    clientThread = ClientThread(clientAddress, clientSockt)
    clientThread.start()
