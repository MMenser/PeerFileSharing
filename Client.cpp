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
#include <poll.h>

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
    cout << "client: connected to " << s << endl;
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

void handleServerMessage(const string& message) {
    if (message.find("wants to connect to you") != string::npos) {
        cout << message << flush;
    }
    else if (message.substr(0, 15) == "/makeconnection") { // Requested side
        string peerIP = message.substr(16);
        if (!peerIP.empty() && peerIP.back() == '\n') { // Removes newline
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
    else if (message.find("/acceptconnection") != string::npos) { // Requestor side
        cout << "Peer accepted! ";
        // The listening socket will handle the incoming connection in the main poll loop
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
    }
    // All other messages from server
    else {
        cout << "Server: " << message << flush;
    }
}

void handlePeerMessage(const string& message) {
    cout << "Peer: " << message << flush;
}

void runClient(const string& username) {
    // Set up poll array
    struct pollfd fds[4];  // stdin, server, listening socket, peer
    int nfds = 0;
    
    // Add stdin (fd 0)
    fds[nfds].fd = STDIN_FILENO;
    fds[nfds].events = POLLIN;
    nfds++;
    
    // Add server socket
    fds[nfds].fd = serverSockFD;
    fds[nfds].events = POLLIN;
    nfds++;
    
    // Send username to server
    if (send(serverSockFD, username.c_str(), username.length(), 0) == -1) {
        perror("send username");
        return;
    }
    
    cout << "------- Enter messages and send with enter -------" << endl;
    
    string stdinBuffer = "";
    string serverBuffer = "";
    string peerBuffer = "";
    
    while (true) {
        // Rebuild poll array dynamically
        nfds = 0;
        
        // stdin
        fds[nfds].fd = STDIN_FILENO;
        fds[nfds].events = POLLIN;
        nfds++;
        
        // server socket (if still connected)
        if (serverSockFD != -1) {
            fds[nfds].fd = serverSockFD;
            fds[nfds].events = POLLIN;
            nfds++;
        }
        
        // listening socket (if active)
        if (listeningSockFD != -1) {
            fds[nfds].fd = listeningSockFD;
            fds[nfds].events = POLLIN;
            nfds++;
        }
        
        // peer socket (if connected)
        if (peerSockFD != -1) {
            fds[nfds].fd = peerSockFD;
            fds[nfds].events = POLLIN;
            nfds++;
        }
        
        // Wait for activity
        int poll_count = poll(fds, nfds, -1);
        
        if (poll_count == -1) {
            perror("poll");
            break;
        }
        
        // Check which sockets have activity
        for (int i = 0; i < nfds; i++) {
            if (!(fds[i].revents & POLLIN)) {
                continue;
            }
            
            if (fds[i].fd == STDIN_FILENO) { // Handle user input to standard input 
                char buf[256];
                int numbytes = read(STDIN_FILENO, buf, sizeof buf - 1);
                if (numbytes <= 0) {
                    cout << "Exiting..." << endl;
                    return;
                }
                
                buf[numbytes] = '\0';
                stdinBuffer += string(buf);
                
                size_t pos;
                while ((pos = stdinBuffer.find('\n')) != string::npos) {
                    string line = stdinBuffer.substr(0, pos);
                    stdinBuffer.erase(0, pos + 1);
                    
                    if (line.substr(0, 8) == "/connect") { // Prepare to accept incoming connection 
                        if (listeningSockFD == -1) {
                            listeningSockFD = createListeningSocket("4000");
                            if (listeningSockFD == -1) {
                                cerr << "Failed to create listening socket" << endl;
                                continue;
                            }
                        }
                    }
                    
                    line += "\n";
                    if (peerSockFD != -1) { // Connected to peer, send messages there
                        if (send(peerSockFD, line.c_str(), line.length(), 0) == -1) {
                            perror("send to peer");
                            close(peerSockFD);
                            peerSockFD = -1;
                        }
                    } else if (serverSockFD != -1) { // Connceted to server, send messages there
                        if (send(serverSockFD, line.c_str(), line.length(), 0) == -1) {
                            perror("send to server");
                            close(serverSockFD);
                            serverSockFD = -1;
                        }
                    }
                }
            }
            // Handle server socket
            else if (fds[i].fd == serverSockFD) {
                char buf[256];
                int numbytes = recv(serverSockFD, buf, sizeof buf - 1, 0);
                
                if (numbytes <= 0) {
                    if (numbytes == 0) {
                        cout << "Server disconnected" << endl;
                    } else {
                        perror("recv from server");
                    }
                    close(serverSockFD);
                    serverSockFD = -1;
                    continue;
                }
                
                buf[numbytes] = '\0';
                serverBuffer += string(buf);
                
                // Process complete messages (might not have \n)
                handleServerMessage(serverBuffer);
                serverBuffer = "";
            }
            // Handle listening socket (new peer connection)
            else if (fds[i].fd == listeningSockFD) {
                acceptPeerConnection();
            }
            // Handle peer socket
            else if (fds[i].fd == peerSockFD) {
                char buf[256];
                int numbytes = recv(peerSockFD, buf, sizeof buf - 1, 0);
                
                if (numbytes <= 0) {
                    if (numbytes == 0) {
                        cout << "Peer disconnected" << endl;
                    } else {
                        perror("recv from peer");
                    }
                    close(peerSockFD);
                    peerSockFD = -1;
                    continue;
                }
                
                buf[numbytes] = '\0';
                peerBuffer += string(buf);
                
                // Process complete messages
                size_t pos;
                while ((pos = peerBuffer.find('\n')) != string::npos) {
                    string message = peerBuffer.substr(0, pos);
                    peerBuffer.erase(0, pos + 1);
                    
                    if (!message.empty()) {
                        handlePeerMessage(message + "\n");
                    }
                }
            }
        }
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
   
    runClient(username);
    
    // Cleanup
    if (serverSockFD != -1) close(serverSockFD);
    if (listeningSockFD != -1) close(listeningSockFD);
    if (peerSockFD != -1) close(peerSockFD);
    
    return 0;
}