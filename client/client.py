"""
    Usage: python3 TCPClient3.py localhost 12000

    Thomas Davie z5263970, adapted from example code from:
    Wei Song (Tutor for COMP3331/9331)
"""
import json
from socket import *
import sys


NAME = None

#Server would be running on the same host as Client
if len(sys.argv) != 3:
    print("\n===== Error usage, python3 TCPClient3.py SERVER_IP SERVER_PORT ======\n")
    exit(0)
serverHost = sys.argv[1]
serverPort = int(sys.argv[2])
serverAddress = (serverHost, serverPort)

# define a socket for the client side, it would be used to communicate with the server
clientSocket = socket(AF_INET, SOCK_STREAM)

# build connection with the server and send message to it
clientSocket.connect(serverAddress)


"""
    APIs
"""
def auth_request():
    name = input("Name: ")
    password = input("Password: ")
    clientSocket.sendall((f"AUT {name} {password}").encode())

    # receive response from the server
    data = clientSocket.recv(1024)
    receivedMessage = data.decode()
    print(receivedMessage)
    # todo this should be more robust
    if "please try again" in receivedMessage:
        auth_request()

    # todo open UDP connection
    # clientSocket.sendall("AUT ")

    return name

'''
    EDG: Generate edge data
'''
def generate_data(name, fileID, dataAmount):
    try:
        with open(f"{name}-{fileID}.txt", "w") as f:
            for x in range(int(dataAmount)):
                f.write(str(x)+'\n')
        return False
    except Exception as e:
        return e

'''
    Edge device sends data to server 
'''
def send_data(name, fileID):
    # open file
    try:
        file = b''
        with open(f"{name}-{fileID}.txt", "rb") as f:
            file = f.read()

        # send intiial message to server
        clientSocket.sendall((f"UED {fileID}").encode())

        # wait for response
        data = clientSocket.recv(1024)
        receivedMessage = data.decode()

        # send file
        clientSocket.sendall(file)

        # wait for response
        data = clientSocket.recv(1024)
        if "OK" in data.decode():
            print("File sent successfully")
        else:
            print("Server reported error receiving file!")
    except Exception as e:
        return e
    
'''
    Request server to do a computation operation (SUM, AVERAGE, MAX, MIN. SUM) on fileID
'''
def request_compute(fileID, computationOperation):
    # send request
    clientSocket.sendall((f"SCS {fileID} {computationOperation}").encode())

    # wait for response
    data = clientSocket.recv(1024)
    receivedMessage = parse_request(data.decode())

    # return response
    if receivedMessage["arguments"][2] == "OK":
        print(f'result: {receivedMessage["arguments"][3]}')
    else:
        return True
    

'''
    Edge device deletes a file stored on server
'''
def request_delete(fileID):
    # send request
    clientSocket.sendall((f"DTE {fileID}").encode())

    # wait for response
    data = clientSocket.recv(1024)
    receivedMessage = parse_request(data.decode())

    # return response
    if receivedMessage["arguments"][2] == "OK":
        print(f'Deleted file "{receivedMessage["arguments"][1]}" successfully')
    else:
        print(f'Server failed to delete file "{receivedMessage["arguments"][1]}"')
        return False

'''
    Edge device requests a list of all other edge devics from server
'''
def request_list_edge_devices():
    # send request
    clientSocket.sendall("AED".encode())

    # get response
    data = clientSocket.recv(2048)
    receivedMessage = data.decode()

    print(json.dumps(receivedMessage[4:], indent=2))
    

'''
    Edge device requests to leave the network
'''
def remove_edge_device():
    # remove device from datastructures
    clientSocket.sendall("OUT".encode())

    # get response
    data = clientSocket.recv(1024)
    receivedMessage = data.decode()

    if "OUT" in receivedMessage:
        print("Disconnected from server")
        return False
    else:
        print("Something went wrong while trying to disconnect from server. Exiting anyway...")
        return True

def parse_request(rq):
        return {"method": rq[:3], "arguments": rq.rsplit(" ")}


while True:    
    # auth
    while NAME is None:
        print("===== Please log in =====\n")
        NAME = auth_request()

    # main command loop
    message = input("===== Please enter a command: =====\n")    
    parsed_rq = parse_request(message)
    
    # exit
    if parsed_rq["method"] == "exit":
        # close the socket
        clientSocket.close()
        sys.exit()

    # EDG
    elif parsed_rq["method"] == "EDG":
        fileID = parsed_rq["arguments"][1]
        dataAmount = parsed_rq["arguments"][2]
        
        # run request
        error = generate_data(NAME, fileID, dataAmount)
        
        # error handling
        if error:
            print(f'ERROR: "{error}", while generating file')
        else:
            print(f"===== Succesfully generated data of length {dataAmount} =====")

    # UED
    elif parsed_rq["method"] == "UED":
        fileID = parsed_rq["arguments"][1]
        
        # run request
        error = send_data(NAME, fileID)

        # error handling
        if error:
            print(f'ERROR: "{error}", while uploading file')
        else:
            print(f"===== Succesfully uploaded file {fileID} =====")
    
    # SCS
    elif parsed_rq["method"] == "SCS":
        if len(parsed_rq["arguments"]) < 3:
            print("Incorrect arguments supplied for operation SCS!")
        
        fileID = parsed_rq["arguments"][1]
        computationOperation = parsed_rq["arguments"][2]
        
        # run request
        error = request_compute(fileID, computationOperation)

        # error handling
        if error:
            print(f'ERROR: "{error}", while requesting compute')

    # DTE
    elif parsed_rq["method"] == "DTE":
        if len(parsed_rq["arguments"]) < 2:
            print("Incorrect arguments supplied for operation SCS!")

        fileID = parsed_rq["arguments"][1]
        
        # run request
        error = request_delete(fileID)

        # error handling
        if error:
            print(f'ERROR: "{error}", while requesting delete')

    # AED
    elif parsed_rq["method"] == "AED":
        # run request
        error = request_list_edge_devices()

        # error handling
        if error:
            print(f'ERROR: "{error}", while requesting edge devices list')

    # OUT
    elif parsed_rq["method"] == "OUT":
        # run request
        error = remove_edge_device()

        # error handling
        if error:
            print(f'ERROR: "{error}", while requesting OUT')

        # close the socket
        clientSocket.close()
        sys.exit()

