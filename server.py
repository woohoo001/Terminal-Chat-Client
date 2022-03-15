from socket import *
from threading import Thread
import sys
import json
import time

database = {
    "users" : {
        # "hans" : {"is_online" : True, "client_connection": , "last_login_time" : ,}
    }

}

flag = 0

OK = 200
BAD_INPUT = 400
ACCESS_ERROR = 403

# Custom error definitions
class Error(Exception):
    pass
class LoginError(Error):
    pass
class AlreadyLogedInError(Error):
    pass
class BlockedError(Error):
    pass
class InvalidCommandError(Error):
    pass

class ClientThread(Thread):
    def __init__(self, client_addr, client_connection, cred_data, block_duration, timeout):
        Thread.__init__(self)
        self.client_addr = client_addr
        self.client_connection = client_connection
        self.cred_data = cred_data
        self.block_duration = block_duration
        self.timeout = timeout
        self.username = ""
        self.clientAlive = True

        print("Connection established from " + str(client_addr))

    def run(self):
        self.processLogin(self.client_connection, self.cred_data, self.block_duration)
        global database
        while self.clientAlive:
            try:
                self.client_connection.settimeout(int(self.timeout))
                client_packet = json.loads(self.client_connection.recv(1024).decode())
                
                if type(client_packet["data"]) is str:
                    command = client_packet["data"].split()
                    print(command[0] + " from " + self.username)
                    try:
                        if command[0] == "logout":
                            self.clientAlive = False
                        elif command[0] == "whoelse":
                            self.sendWhoelse(self.client_connection)
                        elif command[0] == "whoelsesince":
                            time = int(command[1])
                            self.sendWhoelsesince(time, self.client_connection)
                        elif command[0] == "broadcast":
                            message = " ".join(command[1:])
                            if message == " ":
                                continue
                            self.broadcastMessage(message)
                        elif command[0] == "message":
                            user = command[1]
                            message = " ".join(command[2:])
                            if message == " ":
                                continue
                            self.message(user, message)
                        elif command[0] == "block":
                            user = command[1]
                            self.blockUser(user)
                        elif command[0] == "unblock":
                            user = command[1]
                            self.unblockUser(user)
                        elif command[0] == "startprivate":
                            user = command[1]
                            self.startPrivate(user)
                        else:
                            self.sendToClient(BAD_INPUT, "Invalid Command!", self.client_connection)
                    except IndexError:
                        self.sendToClient(BAD_INPUT, "Invalid Command!", self.client_connection)

                elif client_packet["status"] == "P2P_listen_resp":
                    database["users"][self.username]["p2p_peer_port_number"] = client_packet["data"]
                    global flag
                    flag = 1

            except timeout:
                self.clientAlive = False

        database["users"][self.username]["is_online"] = False
        database["users"][self.username]["client_connection"] = None
        self.broadcastStatus(False, self.username)
        self.sendToClient("EXIT", "", self.client_connection)
        self.client_connection.close()
        sys.exit(0)

    def processLogin(self, client_connection, cred_data, block_duration):
        global database
        fail_login_count = 0
        while True:
            client_packet = json.loads(client_connection.recv(1024).decode())
            credentials = client_packet["data"]
            try:
                is_new_user = self.isNewUser(credentials, cred_data)
                if (is_new_user):
                    # Register new user
                    password_message = "This is a new user. Please enter a password"
                    self.sendToClient(OK, password_message, client_connection)
                    
                    client_packet = json.loads(client_connection.recv(1024).decode())
                    password = client_packet["data"]["password"]
                    
                    login_message = "New User Registered!"
                    print("Successful register from " + credentials["username"])
                    cred_file = open("credentials.txt", "a")
                    cred_file.write("\n" + credentials["username"] + " " + password)
                    cred_file.close()

                    database["users"][credentials["username"]] = {}
                    database["users"][credentials["username"]]["is_online"] = True
                    database["users"][credentials["username"]]["last_login_time"] = time.time()
                    database["users"][credentials["username"]]["offline_messages"] = []
                    database["users"][credentials["username"]]["blocklist"] = []
                    database["users"][credentials["username"]]["unblock_time"] = float(0)
                    database["users"][credentials["username"]]["has_p2p_connection"] = False
                    database["users"][credentials["username"]]["p2p_peer_port_nummber"] = None
                else:
                    if time.time() < database["users"][credentials["username"]]["unblock_time"]:
                        raise BlockedError
                    
                    self.sendToClient(OK, None, client_connection)
                    client_packet = json.loads(client_connection.recv(1024).decode())
                    password = client_packet["data"]["password"]
                    credentials["password"] = password
                    
                    self.verifyLogin(credentials, cred_data)
                    login_message = "Login successful!"
                    print("Successful login from " + credentials["username"])
                    
                    database["users"][credentials["username"]]["is_online"] = True
                    database["users"][credentials["username"]]["last_login_time"] = time.time()
                    
                self.username = credentials["username"]
                self.sendToClient(OK, login_message, client_connection)
                
                database["users"][credentials["username"]]["client_connection"] = client_connection
                
                # Broadcast presense.
                self.broadcastStatus(True, self.username)
                
                if database["users"][self.username]["offline_messages"] != []:
                    # Send message recevied while client is offline. Thread sleeps to allow time for socket buffer to clear
                    time.sleep(0.5)
                    self.sendToClient(OK, database["users"][self.username]["offline_messages"], self.client_connection)
                    # Clear after sending
                    database["users"][self.username]["offline_messages"] = []
                break
            except LoginError:
                fail_login_count += 1
                if fail_login_count >= 3: 
                    login_message = "Your account is blocked due to multiple login failures. Try again in " + block_duration + " seconds"
                    database["users"][credentials["username"]]["unblock_time"] = time.time() + float(block_duration)
                    self.sendToClient("BLOCKED", login_message, client_connection)
                    self.clientAlive = False
                else: 
                    login_message = "Username or password incorrect"
                    self.sendToClient(ACCESS_ERROR, login_message, client_connection)
            except AlreadyLogedInError:
                login_message = "User is already loged in"
                self.sendToClient(ACCESS_ERROR, login_message, client_connection)
            except BlockedError:
                message = "Your account is blocked, try again later"
                self.sendToClient("BLOCKED", message, client_connection)
                self.clientAlive = False

    # Traverses cred_data list to verify username and password pair. Return True if correct.
    def verifyLogin(self, credentials, cred_data):
        for user in cred_data:
            info = user.split()
            if credentials["username"] == info[0] and credentials["password"] == info[1]:
                if self.isOnline(credentials["username"]):
                    raise AlreadyLogedInError
                return
            elif credentials["username"] == info[0] and credentials["password"] != info[1]:
                raise LoginError

    def isNewUser(self, credentials, cred_data):
        for user in cred_data:
            info = user.split()
            if credentials["username"] == info[0]:
                return False
        return True


    def isOnline(self, username):
        global database
        return database["users"][username]["is_online"]


    # Sends data from arguments to client. Returns the response messages from other side 
    def sendToClient(self, status, data, client_connection):
        packet = self.generatePacket(status, data)
        client_connection.sendall(json.dumps(packet).encode())

    def generatePacket(self, status, data):
        packet = {
            "status" : status,
            "data" : data
        }
        return packet
    
    # Sends a presense broadcast to all online users but current user and blocked users
    def broadcastStatus(self, is_online, username):
        global database
        key_list = database["users"].keys()
        message = ""
        
        for user in key_list:
            if user != username and self.isOnline(user) and self.isBlocking(user) == False:
                if is_online:
                    message = username + " is now online!"
                else:
                    message = username + " is now offline!"
                self.sendToClient(OK, message, database["users"][user]["client_connection"])
        
    def sendWhoelse(self, client_connection):
        global database
        key_list = database["users"].keys()
        users_online = []

        for user in key_list:
            if user != self.username and self.isOnline(user) and self.isBlockedBy(user) == False:
                users_online.append(user)
                
        self.sendToClient(OK, users_online, client_connection)

    def sendWhoelsesince(self, time_since, client_connection):
        global database
        curr_time = time.time()
        key_list = database["users"].keys()
        users_online_since = []

        for user in key_list:
            if user != self.username and self.isBlockedBy(user) == False and database["users"][user]["last_login_time"] > curr_time - float(time_since):
                users_online_since.append(user)
        
        self.sendToClient(OK, users_online_since, client_connection)

    def broadcastMessage(self, message):
        global database
        message = self.username + ": " + message
        key_list = database["users"].keys()
        any_blocked = False

        for user in key_list:
            if user != self.username and self.isOnline(user) and self.isBlockedBy(user) == False:
                self.sendToClient(OK, message, database["users"][user]["client_connection"])
            elif self.isBlockedBy(user):
                any_blocked = True
        if any_blocked:
            message = "Message could not be sent to some recipients"
            self.sendToClient(OK, message, self.client_connection)
                
    def message(self, user, message):
        global database
        message = self.username + ": " + message
        key_list = database["users"].keys()
        
        if user not in key_list:
            message = "User doesn't exist!"
            self.sendToClient(BAD_INPUT, message, self.client_connection)
            return
        
        if user == self.username:
            message = "Cannot send message to self"
            self.sendToClient(BAD_INPUT, message, self.client_connection)
            return 
        
        # If user is online send message immediately, else store for later.
        if self.isOnline(user) and self.isBlockedBy(user) == False:
            self.sendToClient(OK, message, database["users"][user]["client_connection"])
        elif self.isBlockedBy(user):
            blocked_message = "You are not allowed to message this user!"
            self.sendToClient(OK, blocked_message, self.client_connection)
        else:
            database["users"][user]["offline_messages"].append(message)
            
    def blockUser(self, user):
        global database
        key_list = database["users"].keys()
        
        if user not in key_list:
            message = "User doesn't exist!"
            self.sendToClient(BAD_INPUT, message, self.client_connection)
            return 
        if user == self.username:
            message = "Cannot block self"
            self.sendToClient(BAD_INPUT, message, self.client_connection)
            return
        
        database["users"][self.username]["blocklist"].append(user)
        
        message = user + " is now blocked!"
        self.sendToClient(OK, message, self.client_connection)
        
    def unblockUser(self, user):
        global database
        key_list = database["users"].keys()
        
        if user not in key_list:
            message = "User doesn't exist!"
            self.sendToClient(BAD_INPUT, message, self.client_connection)
            return 
        if user == self.username:
            message = "Cannot unblock self"
            self.sendToClient(BAD_INPUT, message, self.client_connection)
            return
        if user not in database["users"][self.username]["blocklist"]:
            message = "User is not blocked"
            self.sendToClient(BAD_INPUT, message, self.client_connection)
            return
        
        database["users"][self.username]["blocklist"].remove(user)
        
        message = user + " is now unblocked!"
        self.sendToClient(OK, message, self.client_connection)
        
    def isBlockedBy(self, user):
        global database
        
        if self.username in database["users"][user]["blocklist"]:
            return True
        
        return False
    
    def isBlocking(self, user):
        global database
        
        if user in database["users"][self.username]["blocklist"]:
            return True
        return False
    
    def startPrivate(self, user):
        global database
        key_list = database["users"].keys()
        
        # Process error conditions
        if user == self.username:
            err_msg = "Cannot start private with self!"
            self.sendToClient(BAD_INPUT, err_msg, self.client_connection)
            return
        if user not in key_list:
            err_msg = "User does not exist!"
            self.sendToClient(BAD_INPUT, err_msg, self.client_connection)
            return
        if self.isOnline(user) == False:
            err_msg = "User is not online!"
            self.sendToClient(BAD_INPUT, err_msg, self.client_connection)
            return
        if self.isBlockedBy(user):
            err_msg = "You are not allowed to interact with this user!"
            self.sendToClient(BAD_INPUT, err_msg, self.client_connection)
            return
        
        # Ask user permission for private chat
        message = self.username + " would like to private chat with you: Y / N"
        self.sendToClient(OK, message, database["users"][user]["client_connection"])
        
        client_packet = json.loads(database["users"][user]["client_connection"].recv(1024).decode())
        resp = client_packet["data"]
        
        if (resp == "N"):
            message = user + " declined your private chat"
            self.sendToClient(OK, message, self.client_connection)
            return
        elif (resp != "Y"):
            message = "Invalid response!"
            self.sendToClient(BAD_INPUT, message, database["users"][user]["client_connection"])
            return
        
        # Send details of peer to each other.
        peer_info = {
            "user" : self.username,
            "timeout" : int(self.timeout)
        }
        self.sendToClient("P2P_listen", peer_info, database["users"][user]["client_connection"])
        
        global flag
        flag = 0
        while flag == 0:
            continue
        
        p2p_listen_port_num = database["users"][user]["p2p_peer_port_number"]
        peer_info = {
            "user" : user,
            "port_number" : p2p_listen_port_num,
            "timeout" : int(self.timeout)
        }
        self.sendToClient("P2P_init", peer_info, self.client_connection)
    
def main():
    # Initialise command line arguments
    server_port = (sys.argv[1])
    block_duration = sys.argv[2]
    timeout = sys.argv[3]

    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.bind(("localhost", int(server_port)))

    cred_file = open("credentials.txt", "r")
    cred_data = cred_file.readlines()
    initialise_database(cred_data)
    cred_file.close()

    while True:
        server_socket.listen(1)
        print("Server listening on port " + server_port)

        client_connection, addr = server_socket.accept()
        clientThread = ClientThread(addr, client_connection, cred_data, block_duration, timeout)
        clientThread.start()
    


def initialise_database(data):
    global database
    for user in data:
        username = user.split()[0]
        database["users"][username] = {}
        
        database["users"][username]["is_online"] = False
        database["users"][username]["client_connection"] = None
        database["users"][username]["last_login_time"] = float(0)
        database["users"][username]["offline_messages"] = []
        database["users"][username]["blocklist"] = []
        database["users"][username]["unblock_time"] = float(0)
        database["users"][username]["p2p_peer_port_number"] = None
if __name__ == "__main__":
    main()