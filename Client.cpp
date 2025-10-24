#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>

using namespace std;

int listeningSockFD = -1;
int serverSockFD = -1;
int peerSockFD = -1;

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int createListeningSocket(string port) {
    int sockfd;
    struct addrinfo hints{}, *servinfo, *p;
    int yes = 1;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, port.c_str(), &hints, &servinfo)) != 0) {
        cerr << "getaddrinfo: " << gai_strerror(rv) << endl;
        return -1;
    }

    // loop through all results and bind to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("peer: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("setsockopt");
            close(sockfd);
            continue;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("peer: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo);

    if (p == NULL) {
        cerr << "peer: failed to bind" << endl;
        return -1;
    }

    if (listen(sockfd, 1) == -1) {
        perror("listen");
        close(sockfd);
        return -1;
    }

    cout << "Peer listening on port " << port << endl;
    return sockfd;
}

int connectToSocket(const char* ip, string port = "3490") {
    int sockfd;  
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    if ((rv = getaddrinfo(ip, port.c_str(), &hints, &servinfo)) != 0) {
        cerr << "getaddrinfo: " << gai_strerror(rv) << endl;
        return -1;
    }
    
    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }
        
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }
        
        break;
    }
    
    if (p == NULL) {
        cerr << "client: failed to connect" << endl;
        freeaddrinfo(servinfo);
        return -1;
    }
    
    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);
    cout << "client: connecting to " << sockfd << endl;
    freeaddrinfo(servinfo);
    
    return sockfd; 
}

void closeServerConnection() {
    if (serverSockFD != -1) {
        close(serverSockFD);
        serverSockFD = -1;
    }
}

void acceptPeerConnection() {
    if (listeningSockFD == -1) {
        cerr << "No listening socket available" << endl;
        return;
    }
    
    struct sockaddr_storage their_addr;
    socklen_t sin_size = sizeof their_addr;
    
    cout << "Waiting for peer to connect..." << endl;
    peerSockFD = accept(listeningSockFD, (struct sockaddr *)&their_addr, &sin_size);
    
    if (peerSockFD == -1) {
        perror("accept");
        return;
    }
    
    char s[INET6_ADDRSTRLEN];
    inet_ntop(their_addr.ss_family,
              get_in_addr((struct sockaddr *)&their_addr),
              s, sizeof s);
    
    cout << "Peer connected from " << s << endl;
    
    // Close listening socket as we only accept one connection
    close(listeningSockFD);
    listeningSockFD = -1;
    
    // Close server connection
    closeServerConnection();
}

void receiveMessages(int sockfd) {
    int numbytes;
    char buf[256];
    while ((numbytes = recv(sockfd, buf, sizeof buf - 1, 0)) > 0) {
        buf[numbytes] = '\0';
        string message = string(buf);

        // Handle connection request (y/n prompt from server)
        if (message.find("Connection request from") != string::npos) {
            cout << message << flush;
            // User will manually type /accept <username> or /decline <username>
        }
        // Handle /makeconnection command from server (after accepting)
        else if (message.substr(0, 15) == "/makeconnection") {
            string peerIP = message.substr(16);
            // Remove newline if present
            if (!peerIP.empty() && peerIP.back() == '\n') {
                peerIP.pop_back();
            }
            
            cout << "Connecting to peer at " << peerIP << endl;
            closeServerConnection();
            
            peerSockFD = connectToSocket(peerIP.c_str(), "4000");
            if (peerSockFD != -1) {
                if (send(peerSockFD, "hello", 5, 0) == -1) {
                    perror("send to peer");
                } else {
                    cout << "Connected to peer!" << endl;
                }
            } else {
                cerr << "Failed to connect to peer" << endl;
            }
        }
        // Handle "Connection accepted" message (requestor side)
        else if (message.find("/acceptconnection") != string::npos) {
            cout << message << flush;
            // Now accept the incoming peer connection
            cout << "Accepting incoming peer connection..." << endl;
            acceptPeerConnection();
        }
        // Handle /declined message from server
        else if (message == "/declined" || message == "/declined\n") {
            cout << "Connection declined by the peer." << endl;
            // Close listening socket if it exists
            if (listeningSockFD != -1) {
                close(listeningSockFD);
                listeningSockFD = -1;
            }
        }
        // Handle "Located" message (waiting for peer to accept)
        else if (message.find("Located") != string::npos && message.find("waiting") != string::npos) {
            cout << message << flush;
            // Now we wait for peer to accept, which will trigger acceptPeerConnection
        }
        // All other messages from server
        else {
            cout << "Server: " << message << flush;
        }
    }
    
    if (numbytes == 0) {
        cout << "\nConnection closed" << endl;
    } else {
        perror("recv");
    }
    exit(0);
}

void openFork(int sockfd, const string& username, bool isServer) {
    // BEFORE forking: Handle initial server communication
    if (isServer) {        
        // Send username
        if (send(sockfd, username.c_str(), username.length(), 0) == -1) {
            perror("send");
            exit(1);
        }
    }
    
    // NOW fork after initial setup is complete
    pid_t pid = fork();
   
    if (pid == -1) {
        perror("fork");
        exit(1);
    }
   
    if (pid == 0) {
        // Child process: receive messages
        receiveMessages(sockfd);
    } else {
        // Parent process: send messages
        cout << "------- Enter messages and send with enter -------" << endl;
        string line;
        while (getline(cin, line)) {
            line += "\n";
            
            // Start listening when user wants to connect
            if (line.substr(0, 8) == "/connect") {
                listeningSockFD = createListeningSocket("4000");
                cout << "Listening socket created on port 4000" << endl;
                if (listeningSockFD == -1) {
                    cerr << "Failed to create listening socket" << endl;
                    continue;
                }
            }
            
            // Send the command to server
            if (send(sockfd, line.c_str(), line.length(), 0) == -1) {
                perror("send");
                break;
            }
        }
        
        cout << "\nclient: closing connection" << endl;
        close(sockfd);
        kill(pid, SIGTERM);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        cerr << "usage: client username" << endl;
        exit(1);
    }
    
    string username = argv[1];
    serverSockFD = connectToSocket("127.0.0.1", "3490");
    
    if (serverSockFD == -1) {
        cerr << "Failed to connect to server" << endl;
        return 1;
    }
   
    openFork(serverSockFD, username, true);
    return 0;
}