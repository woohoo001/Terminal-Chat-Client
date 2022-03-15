from socket import *
from threading import Thread
import os
import sys
import json
import random
from time import time

NA = 0
OK = 200
BAD_INPUT = 400
ACCESS_ERROR = 403

resp_packet = {}
# flag = 0 while cause sending thread to pause until receiving thread resolves
flag = 0
p2p_socket_global = None
p2p_connection_global = None
p2p_connected_to = None
username_global = None

class SendThread(Thread):
    def __init__(self, client_socket):
        Thread.__init__(self)
        self.client_socket = client_socket

    def run(self):
        while True:
            global resp_packet
            global flag
            global p2p_socket_global
            global p2p_connection_global
            global p2p_connected_to
            global username_global
            
         # Prompt username and password
            username = input("Username: ")

            # Send credentials
            credentials = {
                "username" : username
            }

            self.sendToServer(self.client_socket, credentials)
            
            flag = 0
            while flag == 0:
                continue
            
            password = input("Password: ")
            credentials = {
                "password" : password
            }
            
            self.sendToServer(self.client_socket, credentials)
            
            flag = 0
            while flag == 0:
                continue
            
            login_resp = resp_packet
            
            if login_resp["status"] == OK:
                print("Welcome " + username)
                username_global = username
                break
            if login_resp["status"] == "BLOCKED":
                sys.exit(0)
    
        self.printValidCmds()

        while True:
            command = input()
            try:
                if command.split()[0] == "private":
                    user = command.split()[1]
                    message = user + "(private): " + " ".join(command.split()[2:])
                    if message == " ":
                        continue
                    if p2p_connection_global == None and p2p_socket_global == None:
                        print("startprivate must be executed first with this user")
                        continue
                    if user == username_global:
                        print("Cannot private message self")
                        continue
                    if user != p2p_connected_to:
                        print("user not valid")
                        continue
                    
                    self.sendToPeer(OK, message)
                elif command.split()[0] == "stopprivate":
                    user = command.split()[1]
                    if p2p_connection_global == None and p2p_socket_global == None:
                        print("startprivate must be executed first with this user")
                        continue
                    if user == username_global:
                        print("Cannot end private message with self")
                        continue
                    if user != p2p_connected_to:
                        print("user not valid")
                        continue
                    message = username_global + " has terminated private chat"
                    self.sendToPeer("P2P_fin", message)
                else:
                    self.sendToServer(self.client_socket, command)
            except IndexError:
                print("Command invalid")
                continue

            if command.split()[0] == "logout":
                if p2p_connection_global != None or p2p_socket_global != None:
                    message = "Peer has logged off"
                    self.sendToPeer("P2P_fin", message)
                sys.exit(0)

    def printValidCmds(self):
        print()
        print("Valid commands: ")
        print("message <user> <message>")
        print("broadcast <message>")
        print("whoelse")
        print("whoelsesince <time>")
        print("block <user>")
        print("unblock <user>")
        print("logout")
        print()
        print("startprivate <user>")
        print("private <user> <message>")
        print("stopprivate <user>")
        print()

    # Sends data from arguments to server. Returns the response messages from other side 
    def sendToServer(self, client_socket, data):
        packet = self.generatePacket(OK, data)
        client_socket.sendall(json.dumps(packet).encode())
        
    def sendToPeer(self, status, data):
        global p2p_connection_global
        global p2p_socket_global
        global p2p_connected_to
        
        packet = self.generatePacket(status, data)
        
        if p2p_socket_global != None and p2p_connection_global == None:
            p2p_socket_global.sendall(json.dumps(packet).encode())
        elif p2p_socket_global == None and p2p_connection_global != None:
            p2p_connection_global.sendall(json.dumps(packet).encode())
            
    def generatePacket(self, status, data):
        packet = {
            "status" : status,
            "data" : data
        }
        return packet

class ReceiveThread(Thread):
    def __init__(self, client_socket):
        Thread.__init__(self)
        self.client_socket = client_socket

    def run(self):
        while True:
            
            global resp_packet
            global flag
            global p2p_connected_to
            global p2p_socket_global
            global p2p_connection_global
            
            resp = json.loads(self.client_socket.recv(1024).decode())

            # Used in authentication process
            resp_packet = resp

            if resp["status"] == "EXIT" or resp["status"] == "BLOCKED":
                if resp["status"] == "BLOCKED":
                    print(resp["data"])
                self.client_socket.close()
                sys.exit(0)
            elif resp["status"] == "P2P_init":
                # Create sockets and initiate p2p connection. Then create p2p receive threads
                p2p_socket = socket(AF_INET, SOCK_STREAM)
                
                p2p_port = resp["data"]["port_number"]
                
                p2p_socket.connect(("localhost", p2p_port))
                p2p_connected_to = resp["data"]["user"]
                timeout = resp["data"]["timeout"]
                
                print("P2P connection made to " + p2p_connected_to)
                
                P2PThread = P2PReceiveThread(p2p_socket, None, timeout)
                P2PThread.daemon = True
                P2PThread.start()
                
                p2p_socket_global = p2p_socket
                
                
            elif resp["status"] == "P2P_listen":
                # Create sockets and accept incoming connection. Then create p2p receive threads
                p2p_socket = socket(AF_INET, SOCK_STREAM)
                
                p2p_port = random.randint(1024, 65535)
                p2p_socket.bind(("localhost", p2p_port))
                
                p2p_socket.listen(1)
                
                p2p_connected_to = resp["data"]["user"]
                timeout = resp["data"]["timeout"]
                packet = {
                    "status" : "P2P_listen_resp",
                    "data" : p2p_port
                }
                self.client_socket.sendall(json.dumps(packet).encode())
                
                p2p_connection, addr = p2p_socket.accept()
                print("P2P connection made from " + p2p_connected_to)
                
                P2PThread = P2PReceiveThread(None, p2p_connection, timeout)
                P2PThread.daemon = True
                P2PThread.start()
                
                p2p_connection_global = p2p_connection
            
            if type(resp["data"]) is list:
                for x in resp["data"]:
                    print(x)
            elif resp["data"] != None and resp["status"] != "P2P_init" and resp["status"] != "P2P_listen":
                print(resp["data"])
            flag = 1


class P2PReceiveThread(Thread):
    def __init__(self, p2p_socket, p2p_connection, timeout):
        Thread.__init__(self)
        self.p2p_socket = p2p_socket
        self.p2p_connection = p2p_connection
        self.p2p_alive = True
        self.timeout = timeout
        
    def run(self):
        global p2p_connected_to
        global p2p_socket_global
        global p2p_connection_global
        
        if (self.p2p_socket != None):
            while self.p2p_alive:
                try:
                    self.p2p_socket.settimeout(self.timeout)
                    resp = json.loads(self.p2p_socket.recv(1024).decode())
                    if resp["status"] == "P2P_fin":
                        self.p2p_alive = False
                        packet = {
                            "status" : "P2P_fin",
                            "data" : None
                        }
                        self.p2p_socket.sendall(json.dumps(packet).encode())
                        self.p2p_socket.close()
                    if resp["data"] != None:
                        print(resp["data"])
                except timeout:
                    self.p2p_alive = False
    
        elif (self.p2p_connection != None):
            while self.p2p_alive:
                try:
                    self.p2p_connection.settimeout(self.timeout)
                    resp = json.loads(self.p2p_connection.recv(1024).decode())
                    if resp["status"] == "P2P_fin":
                        self.p2p_alive = False
                        packet = {
                            "status" : "P2P_fin",
                            "data" : None
                        }
                        self.p2p_connection.sendall(json.dumps(packet).encode())
                        self.p2p_connection.close()
                    if resp["data"] != None:
                        print(resp["data"])
                except timeout:
                    self.p2p_alive = False
                    packet = {
                            "status" : "P2P_fin",
                            "data" : "Peer has timed out"
                    }
                    self.p2p_connection.sendall(json.dumps(packet).encode())
                    self.p2p_connection.close()
                    
        p2p_socket_global = None
        p2p_connection_global = None
        p2p_connected_to = None
def main():
    server_port = sys.argv[1]

    # Initiate TCP connection
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect(("localhost", int(server_port)))

    sendThread = SendThread(client_socket)
    receiveThread = ReceiveThread(client_socket)

    sendThread.daemon = True
    receiveThread.daemon = True
    
    sendThread.start()
    receiveThread.start()

    while receiveThread.is_alive() == True and sendThread.is_alive() ==  True:
        continue
























if __name__ == "__main__":
    main()