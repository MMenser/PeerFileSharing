#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <vector>
#include <map>
#include "ClientList.cpp"

using namespace std;
const string PORT = "3490";
const int BACKLOG = 10;

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

class Server
{
private:
    int sockfd;
    ClientList &clientList;
    
    // Poll structures
    struct pollfd fds[MAX_CLIENTS];
    int nfds;
    
    // Map to track client state (fd -> {username, ip, buffer})
    struct ClientInfo {
        string username;
        string ip;
        string buffer; // For partial messages
        bool authenticated; // Has sent username
    };
    map<int, ClientInfo> clients;

    int createSocket()
    {
        struct addrinfo hints, *servinfo, *p;
        int yes = 1;
        int rv;

        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;

        if ((rv = getaddrinfo(NULL, PORT.c_str(), &hints, &servinfo)) != 0)
        {
            cerr << "getaddrinfo: " << gai_strerror(rv) << endl;
            exit(1);
        }

        for (p = servinfo; p != NULL; p = p->ai_next)
        {
            if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
            {
                perror("server: socket");
                continue;
            }

            if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
            {
                perror("setsockopt");
                exit(1);
            }

            if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
            {
                close(sockfd);
                perror("server: bind");
                continue;
            }

            break;
        }

        freeaddrinfo(servinfo);

        if (p == NULL)
        {
            cerr << "server: failed to bind" << endl;
            exit(1);
        }

        if (listen(sockfd, BACKLOG) == -1)
        {
            perror("listen");
            exit(1);
        }

        return sockfd;
    }

    void handleConnectionRequest(string message, string &response, const string username) {
        string peerUsername = message.substr(9);
        char* peerIP = clientList.findUserIP(peerUsername);
        if (peerIP == nullptr) {
            response = "User " + peerUsername + " not found or not online.\n";
            return;
        }
        int peerSockFD = clientList.findUserSockFD(peerUsername);
        string connectionRequest = username + " wants to connect to you. Accept? (/accept " + username + " or /decline " + username + ")\n";
        
        cout << "Sending connection request to " << peerUsername << " at " << string(peerIP) << " sockfd " << peerSockFD << endl;
        
        ssize_t bytes_sent = send(peerSockFD, connectionRequest.c_str(), connectionRequest.length(), 0);
        if (bytes_sent == -1) {
            perror("send connection request");
            response = "Failed to send connection request.\n";
        }
        else {
            response = "Located " + peerUsername + " @" + string(peerIP) + " - waiting for peer to accept connection... \n";
        }
    }

    void parseMessage(const string &message, int client_fd, const string &username) {
        string response = "";
        if (message == "/list") {
            response = clientList.getList();
        }
        else if (message.substr(0, 8) == "/connect") {
            cout << "Handling /connect command from " << username << endl;
            if (message.length() <= 9) {
                response = "Usage: /connect <username>\n";
            } 
            else {
                handleConnectionRequest(message, response, username);
            }
        }
        else if (message.substr(0,7) == "/accept") {
            if (message.length() <= 8) {
                response = "Usage: /accept <username>\n";
            } 
            else {
                string peerUsername = message.substr(8);
                char* peerIP = clientList.findUserIP(peerUsername);
                int peerSockFD = clientList.findUserSockFD(peerUsername);
                if (peerIP == nullptr) {
                    response = "User " + peerUsername + " not found or not online.\n";
                }
                else {
                    response = "/makeconnection " + string(peerIP) + "\n";

                    string acceptMessage = "/acceptconnection";
                    if (send(peerSockFD, acceptMessage.c_str(), acceptMessage.length(), 0) == -1) {
                        perror("send accept");
                    }
                }
            }
        }
        else if (message.substr(0,8) == "/decline") {
            if (message.length() <= 9) {
                response = "Usage: /decline <username>\n";
            } 
            else {
                string peerUsername = message.substr(9);
                char* peerIP = clientList.findUserIP(peerUsername);
                int peerSockFD = clientList.findUserSockFD(peerUsername);
                if (peerIP == nullptr) {
                    response = "User " + peerUsername + " not found or not online.\n";
                }
                else {
                    string declineMessage = "/declined";
                    if (send(peerSockFD, declineMessage.c_str(), declineMessage.length(), 0) == -1) {
                        perror("send decline");
                    }
                    else {
                        response = "Declined connection request from " + peerUsername + "\n";
                    }
                }
            }
        }
        else {
            response = "Unknown command.\n";
        }

        if (send(client_fd, response.c_str(), response.length(), 0) == -1) {
            perror("send");
        }
    }

    void handleNewConnection() {
        struct sockaddr_storage their_addr;
        socklen_t sin_size = sizeof their_addr;

        int new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            return;
        }

        char s[INET6_ADDRSTRLEN];
        inet_ntop(their_addr.ss_family,
                  get_in_addr((struct sockaddr *)&their_addr),
                  s, sizeof s);
        cout << "server: got connection from " << s << " on fd=" << new_fd << endl;

        // Add to poll array
        if (nfds < MAX_CLIENTS) {
            fds[nfds].fd = new_fd;
            fds[nfds].events = POLLIN; // Watch for incoming data
            nfds++;

            // Initialize client info
            clients[new_fd] = {
                .username = "",
                .ip = string(s),
                .buffer = "",
                .authenticated = false
            };
        } else {
            cerr << "Too many clients, rejecting connection" << endl;
            close(new_fd);
        }
    }

    void handleClientData(int i) {
        int client_fd = fds[i].fd;
        char buf[256];
        
        int numbytes = recv(client_fd, buf, sizeof buf - 1, 0);
        
        if (numbytes <= 0) {
            // Connection closed or error
            if (numbytes == 0) {
                cout << "server: socket " << client_fd << " hung up" << endl;
            } else {
                perror("recv");
            }
            
            // Remove from ClientList if authenticated
            if (clients[client_fd].authenticated) {
                cout << "server: user '" << clients[client_fd].username << "' disconnected" << endl;
                clientList.remove(client_fd);
            }
            
            // Clean up
            close(client_fd);
            clients.erase(client_fd);
            
            // Remove from poll array (swap with last element)
            fds[i] = fds[nfds - 1];
            nfds--;
            
            return;
        }
        
        buf[numbytes] = '\0';
        
        // If not authenticated, first message is username
        if (!clients[client_fd].authenticated) {
            clients[client_fd].username = string(buf);
            clients[client_fd].authenticated = true;
            
            clientList.add(clients[client_fd].username, client_fd, clients[client_fd].ip);
            cout << "server: user '" << clients[client_fd].username 
                 << "' connected on fd=" << client_fd << endl;
            return;
        }
        
        // Add to buffer
        clients[client_fd].buffer += string(buf);
        
        // Process complete messages (ending with \n)
        size_t pos;
        while ((pos = clients[client_fd].buffer.find('\n')) != string::npos) {
            string message = clients[client_fd].buffer.substr(0, pos);
            clients[client_fd].buffer.erase(0, pos + 1);
            
            if (!message.empty()) {
                cout << "server: received '" << message << "' from " 
                     << clients[client_fd].username << endl;
                parseMessage(message, client_fd, clients[client_fd].username);
            }
        }
    }

public:
    Server(ClientList &list) : clientList(list), nfds(0)
    {
        sockfd = createSocket();
        
        // Add listening socket to poll array
        fds[0].fd = sockfd;
        fds[0].events = POLLIN; // Watch for incoming connections
        nfds = 1;
        
        cout << "server: waiting for connections on port " << PORT << "..." << endl;
    }

    void run()
    {
        while (true)
        {
            // Wait for activity on any socket
            int poll_count = poll(fds, nfds, -1); // -1 = wait indefinitely
            
            if (poll_count == -1) {
                perror("poll");
                exit(1);
            }
            
            // Check which sockets have activity
            for (int i = 0; i < nfds; i++) {
                if (fds[i].revents & POLLIN) {
                    if (fds[i].fd == sockfd) {
                        // Activity on listening socket = new connection
                        handleNewConnection();
                    } else {
                        // Activity on client socket = data to read
                        handleClientData(i);
                    }
                }
            }
        }
    }

    ~Server()
    {
        close(sockfd);
    }
};