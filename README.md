# Terminal-Chat-Client

A chat client that runs on a command line/ terminal.

# 1. Installation
Python3 must be installed onto desktop for chat client to run. 

This can be downloaded here: https://www.python.org/downloads/

The chat client is tested for Python 3.7 and above

# 2. Initiating Server

Open the command line/terminal and execute the server. The server accepts three arguments:  
  
**server_port** : This is the port number which the server will communicate with the clients.  
  
**block_duration** : The duration in seconds for which a user should be blocked after 3 unsuccessful login attempts.  
  
**timeout** : The duration in seconds of inactivity after which the user is forceibly logged off by the server.  
  
The server is initiated by running the following command:  
**py server.py server_port block_duration timeout**  
    
# 3. Initiating Clients  

Clients are initiated in a seperate command line/terminal. The client accepts one argument:  
  
**server_port** : This is the port number being used by the server.
  
The client is initiated by running the following command:  
**py client.py server_port**  
  
The client will ask for credentials. If you are a new user, simply enter a username and the client will prompt for a new password.  
  
Any unreceived messages to the client would be sent by the server after the client logs in.

# 4. Commands Supported by Clients  

After client is logged in. The following commmands are available:  
- **message [user] [message]** : Sends [message] to [user].
- **broadcast [message]** : Sends [message] to all other online users.
- **whoelse** : Displays usernames of all online users.
- **whoelsesince [time]** : Displays usernames of all other users who were logged in at any time within the last [time] seconds.
- **block [user]** : Blocks messages sent from [user] and prevents [user] from checking online status of self.
- **unblock [user]** : Unblocks [user]
- **logout** : Logs the user out

The clients also support a **peer-to-peer** connection where clients are connected directly and not through a central server. All messages will bypass the server.  
  
- **startprivate [user]** : Starts a peer-to-peer connection with [user].
- **private [user] [message]** : Sends [message] to [user] without routing through server.
- **stopprivate [user]** : Disconnects the peer-to-peer connection with [user].


