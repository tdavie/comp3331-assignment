"""
    Usage: python3 TCPserver3.py localhost 12000 3
    
    Thomas Davie z5263970, adapted from example code from:
    Wei Song (Tutor for COMP3331/9331)
"""
from socket import *
from threading import Thread, Lock
import sys, select, os
from datetime import datetime


CURRENT_MAX_AUTH_ID = 0
CURRENT_MAX_UNAUTH_ID = 0
TIMEOUT_SECONDS = 20

# unauthenticated hosts lock
unauth_lock = Lock()
# authenticated hosts lock
auth_lock = Lock()
# shared lock for file io
io_lock = Lock()


# acquire server host and port from command line parameter
if len(sys.argv) != 3:
    print("\n===== Error usage, python3 TCPServer3.py SERVER_PORT NUM_CONSECTUIVE_FAILED_ATTEMPTS ======\n")
    exit(0)

try:
    login = int(sys.argv[2])
    if login < 6 and login > 0:
        MAX_LOGIN_ATTEMPTS = login
    else:
        raise ValueError
except ValueError:
    print("\n===== Error usage, NUM_CONSECTUIVE_FAILED_ATTEMPTS must be an integer between 1 and 5 ======\n")
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


# define global host db for auth
# used for devices which have not yet been authenticated, keeping track of previous logins etc. to enforce rate limiting etc.
unauthenticatedHosts = {
    # "device-name": {
    #     "id": 0,
    #     "ip": "100.100.100.100",
    #     "port": "10000",
    #     "isAuthenticated": False,
    #     "lastAuthAttempt": 0,
    #     "authAttemptCount": 0,
    # }
}
# once a device is authenticated, it is removed from unauthenticatedDevices and added to authenticatedDevices
authenticatedHosts = {
    # "device-name": {
    #     "id": 0,
    #     "ip": "100.100.100.100",
    #     "port": "10000"
    # }
}

# DB Helpers
# __________

def get_host_name_by_IP(hosts, IP):
    # print(hosts)
    # print(IP)
    for key, val in hosts.items():
        if val["ip"] == IP:
            return key
    return False

# write to device log
def log_write(log, message):
    with open(log, "a") as l:
        l.write(message+'\n')

def updateDeviceID(id):
    for host in authenticatedHosts:
        if host["id"] > id:
            host["id"] -= 1

def updateDeviceLog(log, id):
    with open(log, "w") as l:
        lines = l.readlines()
        for line in lines:
            if int(line[:1]) > id:
                line = str(int(line[:1])-1)+line[1:]
            elif int(line[:1]) == id:
                lines.remove(line)
        l.write(lines)                

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
                
                # get lock
                unauth_lock.acquire()
                auth_lock.acquire()

                # add edge device to hosts dict
                global CURRENT_MAX_UNAUTH_ID
                global unauthenticatedHosts

                name = parsed_message["arguments"][1]
                print(unauthenticatedHosts)
                if name not in unauthenticatedHosts:
                    print("Hello")
                    unauthenticatedHosts[name] = {
                        "id": CURRENT_MAX_UNAUTH_ID,
                        "ip": self.clientAddress,
                        "port": self.clientSocket,
                        "lastAuthAttempt": 0,
                        "authAttemptCount": 0,
                        }
                else:
                    unauthenticatedHosts[name] = {
                        "id": CURRENT_MAX_UNAUTH_ID,
                        "ip": self.clientAddress,
                        "port": self.clientSocket,
                        }

                CURRENT_MAX_UNAUTH_ID += 1

                # process login
                self.process_login(parsed_message)

                # release lock
                unauth_lock.release()
                auth_lock.release()


            # UED
            elif parsed_message["method"] == "UED":
                print(f"[recv] New file upload request from {clientAddress}")
                self.receive_file(parsed_message["arguments"][1])

            # SCS
            elif parsed_message["method"] == "SCS":
                print(f"[recv] New compute request from {clientAddress}")
                error = self.do_compute(parsed_message["arguments"][1], parsed_message["arguments"][2])
                if error:
                    print(f"ERROR: {error} while performing compute request from {clientAddress}")

            # DTE
            elif parsed_message["method"] == "DTE":
                print(f"[recv] New delete request from {clientAddress}")
                error = self.delete(parsed_message["arguments"][1])
                if error:
                    print(f"ERROR: {error} while performing delete request from {clientAddress}")

            # AED
            elif parsed_message["method"] == "AED":
                print(f"[recv] New list request from {clientAddress}")
                self.list_edge_devices()
            
            # OUT
            elif parsed_message["method"] == "OUT":
                print(f"[recv] New list request from {clientAddress}")
                error = self.list_edge_devices()
                if error:
                    print(f"ERROR: {error} while performing out request from {clientAddress}")

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

        global unauthenticatedHosts

        # check id edge device is timed out
        if unauthenticatedHosts[name]["authAttemptCount"] > MAX_LOGIN_ATTEMPTS:
            if datetime.strptime(unauthenticatedHosts[name]["lastAuthAttempt"], '%b %d %Y %I:%M%p') + TIMEOUT_SECONDS < datetime.now():
                return
            
        # login loop
        while unauthenticatedHosts[name]["authAttemptCount"] < MAX_LOGIN_ATTEMPTS:
            if self.check_credentials(message):
                response = "\n===== Welcome! ====="
                print('client login successful')
                self.clientSocket.send(response.encode())
               
                # remove device from unauthenticated hosts
                del unauthenticatedHosts[name]

                # add device to authenticated hosts
                global CURRENT_MAX_AUTH_ID
                authenticatedHosts[name] = {
                    "id": CURRENT_MAX_AUTH_ID,
                    "ip": self.clientAddress,
                    "port": self.clientSocket
                }

                CURRENT_MAX_AUTH_ID += 1

                # update device log
                log_write("edge-device-log.txt", f"{authenticatedHosts[name]['id']}; {datetime.now().strftime('%d %B %Y %H:%M:%S')}; {message['arguments'][1]}; {self.clientAddress[0]}; {self.clientAddress[1]}")

                return
            else:
                unauthenticatedHosts[name]["authAttemptCount"] += 1
                
                
                if unauthenticatedHosts[name]['authAttemptCount'] < MAX_LOGIN_ATTEMPTS:
                    # authentication failure
                    response = f"authentication failed, please try again (Attempt {unauthenticatedHosts[name]['authAttemptCount']}/{MAX_LOGIN_ATTEMPTS})"
                    self.clientSocket.send(response.encode())
                    
                    data = self.clientSocket.recv(1024)
                    message = self.parse_request(data.decode())
                    continue

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
    def receive_file(self, fileID):
        # send response to client, wait for tcp stream
        self.clientSocket.sendall(f"UED {fileID}".encode())

        # receive file over TCP stream
        data = self.clientSocket.recv(2048)
        file = data.decode()

        # locks
        auth_lock.acquire()
        io_lock.acquire()

        # write file
        name = get_host_name_by_IP(authenticatedHosts, self.clientAddress)
        try:
            with open(f"{name}-{fileID}.txt", "w") as f:
                f.write(file)
        except Exception as e:
            print(f"ERROR: {e} while writing to file")
            self.clientSocket.sendall(f"UED {fileID} FAIL".encode())

        # acknowledge file receipt
        self.clientSocket.sendall(f"UED {fileID} OK".encode())

        # log file upload
        log_write("upload-log.txt", f"{name}; {datetime.now().strftime('%d %B %Y %H:%M:%S')}; {fileID}; {sum(1 for line in file)}")
        
        auth_lock.release()
        io_lock.release()
    
    '''
        Request server to do a computation operation (SUM, AVERAGE, MAX, MIN. SUM) on fileID
    '''
    def do_compute(self, fileID, computationOperation):
        # open file, parse numbers

        auth_lock.acquire()
        io_lock.acquire()

        hostname = get_host_name_by_IP(authenticatedHosts, self.clientAddress)
        nums = []
        print(f"{hostname}-{fileID}.txt")
        try:
            with open(f"{hostname}-{fileID}.txt", "r") as f:
                for l in f.readlines():
                    nums.append(int(l))
        except Exception as e:
            return e

        auth_lock.release()
        io_lock.release()
        
        # do compute
        result = None
        print(computationOperation)
        if computationOperation == "SUM":
            result = sum(nums)
        elif computationOperation == "AVERAGE":
            result = sum(nums)/len(nums)
        elif computationOperation == "MAX":
            result = max(nums)
        elif computationOperation == "MIN":
            result = min(nums)
        
        print(result)

        # send response
        if result != None:
            self.clientSocket.sendall(f"SCS {fileID} OK {result}".encode())
            print(f"[send] Sent compute result to {clientAddress}")
        else:
            self.clientSocket.sendall(f"SCS {fileID} FAIL".encode())
            print(f"[send] Sent error in compute result to {clientAddress}")
        return False

    '''
        Edge device deletes a file stored on server
    '''
    def delete(self, fileID):
        # delete file
        
        auth_lock.acquire()
        io_lock.acquire()
        
        hostname = get_host_name_by_IP(authenticatedHosts, self.clientAddress)
        dataAmount = 0
        try:
            with open(f"{hostname}-{fileID}.txt") as f:
                dataAmount = sum(1 for line in f)
            os.remove(f"{hostname}-{fileID}.txt")
        except Exception as e:
            self.clientSocket.sendall(f"DTE {fileID} FAIL".encode())
            print(f"[send] Sent error in deleting file to {clientAddress}")
            return e
        # send response
        self.clientSocket.sendall(f"SCS {fileID} OK".encode())
        print(f"[send] Sent acknowledgement of deleting file with fileID '{fileID}' to {clientAddress}")

        # log delete
        log_write("deletion-log.txt", f"{hostname}; {datetime.now().strftime('%d %B %Y %H:%M:%S')}; {fileID}; {dataAmount}")
        
        auth_lock.release()
        io_lock.release()

        return False

    '''
        Edge device requests a list of all other edge devics from server
    '''
    def list_edge_devices(self):
        # send response
        auth_lock.acquire()
        self.clientSocket.sendall(f"AED {authenticatedHosts}".encode())
        auth_lock.release()
        return
   
    '''
        Edge device requests to leave the network
    '''
    def remove_edge_device(self, deviceName):
        # remove device from datastructures
        auth_lock.acquire()
        io_lock.acquire()
        try:
            # update deviceID to keep number sequence continuous
            id = authenticatedHosts[deviceName]
            updateDeviceID(id)

            # update log file
            updateDeviceLog(id)

            del authenticatedHosts[deviceName]

        except Exception as e:
            auth_lock.release()
            io_lock.release()
            
            return e

        auth_lock.release()
        io_lock.release()

        return False
    
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
