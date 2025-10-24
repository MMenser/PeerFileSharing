# P2P File Sharing

Central tracking server keeps a list of active peers. Peers can request the server to connect each other

Once connected, peers have option to send and recieve files. 

Need peers to listen and send messages. Listening should listen to requests for connections and responds with yes or no.
Sending messages should include asking for a connection, sending a file, disconnecting.

Alice requests server to connect her to Bob
Server asks Bob if he wants to connect to Alice
If yes,
    open up socket between Bob and Alice
If no,
    tell Alice that Bob said no

Connection request is being sent to the requestor instead of requested