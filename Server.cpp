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
#include <signal.h>
#include <sys/wait.h>
#include "ClientList.cpp"

using namespace std;
const string PORT = "3490";
const int BACKLOG = 10;

void sigchld_handler(int s)
{
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
    errno = saved_errno;
}

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

    void setupSignalHandler()
    {
        struct sigaction sa;
        sa.sa_handler = sigchld_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        if (sigaction(SIGCHLD, &sa, NULL) == -1)
        {
            perror("sigaction");
            exit(1);
        }
    }

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

    void listenForMessages(int client_fd, const string &client_ip, const string &username) {
        // Receive messages until client disconnects
        char buf[256];
        int numbytes = 0;
        while ((numbytes = recv(client_fd, buf, sizeof buf - 1, 0)) > 0) {
            buf[numbytes] = '\0';
            cout << "server: received '" << buf << "' from " << username << endl;
        }

        if (numbytes == 0) {
            cout << "server: user '" << username << "' disconnected" << endl;
        }
        else {
            perror("recv");
        }

        // Remove client from list
        clientList.remove(client_fd);
        close(client_fd);
        exit(0);
    }

void handleClient(int client_fd, const string& client_ip) {
        close(sockfd); // child doesn't need listener

        // Receive username
        char username_buf[50];
        int numbytes = recv(client_fd, username_buf, sizeof username_buf - 1, 0);
        if (numbytes <= 0) {
            close(client_fd);
            exit(0);
        }
        username_buf[numbytes] = '\0';
        string username(username_buf);
        
        // Add client to list
        clientList.add(username, client_fd, client_ip);
        cout << "server: user '" << username << "' connected from " << client_ip << endl;
        
        // Receive messages until client disconnects
        char buf[256];
        while ((numbytes = recv(client_fd, buf, sizeof buf - 1, 0)) > 0) {
            buf[numbytes - 1] = '\0'; // Remove newline
            parseMessage(buf, client_fd, username);
        }
        
        if (numbytes == 0) {
            cout << "server: user '" << username << "' disconnected" << endl;
        } else {
            perror("recv");
        }
        
        // Remove client from list
        clientList.remove(client_fd);
        close(client_fd);
        exit(0);
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
    cout << "Message: '" << connectionRequest << "'" << endl;
    
    ssize_t bytes_sent = send(peerSockFD, connectionRequest.c_str(), connectionRequest.length(), 0);
    if (bytes_sent == -1) {
        perror("send connection request");
        response = "Failed to send connection request.\n";
    }
    else {
        cout << "Successfully sent " << bytes_sent << " bytes to peer" << endl;
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
        else if (message.substr(0,7) == "/accept") { // Should check whether there is a pending request, otherwise don't allow users to accept
            // We are in the requested POV
            if (message.length() <= 9) {
                response = "Usage: /accept <username>\n";
            } 
            else {
                string peerUsername = message.substr(8);
                char* peerIP = clientList.findUserIP(peerUsername);
                int peerSockFD = clientList.findUserSockFD(peerUsername);
                if (peerIP == nullptr) {
                    response = "User " + peerUsername + " not found or not online.\n";
                    return;
                }
                else {
                    response = "/makeconnection " + string(peerIP) + "\n"; // to the requested

                    string acceptMessage = "/acceptconnection";
                    if (send(peerSockFD, acceptMessage.c_str(), acceptMessage.length(), 0) == -1) { // to the requestor
                        perror("send accept");
                    }
                }

            }
        }
        else if (message.substr(0,8) == "/decline") {
            if (message.length() <= 10) {
                response = "Usage: /decline <username>\n";
            } 
            else {
                string peerUsername = message.substr(9);
                char* peerIP = clientList.findUserIP(peerUsername);
                int peerSockFD = clientList.findUserSockFD(peerUsername);
                if (peerIP == nullptr) {
                    response = "User " + peerUsername + " not found or not online.\n";
                    return;
                }
                string declineMessage = "/declined";
                if (send(peerSockFD, declineMessage.c_str(), declineMessage.length(), 0) == -1) {
                    perror("send decline");
                }
                else {
                    response = "Declined connection request from " + peerUsername + "\n";
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

public:
    Server(ClientList &list) : clientList(list)
    {
        setupSignalHandler();
        sockfd = createSocket();
        cout << "server: waiting for connections on port " << PORT << "..." << endl;
    }

    void run()
    {
        while (true)
        {
            struct sockaddr_storage their_addr;
            socklen_t sin_size = sizeof their_addr;

            int new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
            if (new_fd == -1)
            {
                perror("accept");
                continue;
            }

            char s[INET6_ADDRSTRLEN];
            inet_ntop(their_addr.ss_family,
                      get_in_addr((struct sockaddr *)&their_addr),
                      s, sizeof s);
            cout << "server: got connection from " << s << endl;

            if (!fork())
            {
                handleClient(new_fd, string(s));
            }
            close(new_fd); // parent doesn't need this
        }
    }

    ~Server()
    {
        close(sockfd);
    }
};