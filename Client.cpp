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
#include <vector>
#include <sys/stat.h>

using namespace std;

int listeningSockFD = -1;
int serverSockFD = -1;
int peerSockFD = -1;
vector<string> fileQueue;

// File receiving state
enum ReceiveState { TEXT_MODE, RECEIVING_FILE };
ReceiveState recvState = TEXT_MODE;
FILE* receivingFile = nullptr;
size_t expectedFileSize = 0;
size_t receivedFileSize = 0;
string receivingFileName = "";

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int createListeningSocket(string port)
{
    int sockfd;
    struct addrinfo hints{}, *servinfo, *p;
    int yes = 1;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(NULL, port.c_str(), &hints, &servinfo)) != 0)
    {
        cerr << "getaddrinfo: " << gai_strerror(rv) << endl;
        return -1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            perror("peer: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            perror("setsockopt");
            close(sockfd);
            continue;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            perror("peer: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo);

    if (p == NULL)
    {
        cerr << "peer: failed to bind" << endl;
        return -1;
    }

    if (listen(sockfd, 1) == -1)
    {
        perror("listen");
        close(sockfd);
        return -1;
    }

    cout << "Peer listening on port " << port << endl;
    return sockfd;
}

int connectToSocket(const char *ip, string port = "3490")
{
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(ip, port.c_str(), &hints, &servinfo)) != 0)
    {
        cerr << "getaddrinfo: " << gai_strerror(rv) << endl;
        return -1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            perror("client: connect");
            continue;
        }

        break;
    }

    if (p == NULL)
    {
        cerr << "client: failed to connect" << endl;
        freeaddrinfo(servinfo);
        return -1;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);
    cout << "client: connected to " << s << endl;
    freeaddrinfo(servinfo);

    return sockfd;
}

void closeServerConnection()
{
    if (serverSockFD != -1)
    {
        close(serverSockFD);
        serverSockFD = -1;
    }
}

void acceptPeerConnection()
{
    if (listeningSockFD == -1)
    {
        cerr << "No listening socket available" << endl;
        return;
    }

    struct sockaddr_storage their_addr;
    socklen_t sin_size = sizeof their_addr;

    cout << "Waiting for peer to connect..." << endl;
    peerSockFD = accept(listeningSockFD, (struct sockaddr *)&their_addr, &sin_size);

    if (peerSockFD == -1)
    {
        perror("accept");
        return;
    }

    char s[INET6_ADDRSTRLEN];
    inet_ntop(their_addr.ss_family,
              get_in_addr((struct sockaddr *)&their_addr),
              s, sizeof s);

    cout << "Peer connected from " << s << endl;

    close(listeningSockFD);
    listeningSockFD = -1;

    closeServerConnection();
}

void handleServerMessage(const string &message)
{
    if (message.find("wants to connect to you") != string::npos)
    {
        cout << message << flush;
    }
    else if (message.substr(0, 15) == "/makeconnection")
    {
        string peerIP = message.substr(16);
        if (!peerIP.empty() && peerIP.back() == '\n')
        {
            peerIP.pop_back();
        }

        cout << "Connecting to peer at " << peerIP << endl;
        closeServerConnection();

        peerSockFD = connectToSocket(peerIP.c_str(), "4000");
        if (peerSockFD != -1)
        {
            if (send(peerSockFD, "hello", 5, 0) == -1)
            {
                perror("send to peer");
            }
            else
            {
                cout << "Connected to peer!" << endl;
            }
        }
        else
        {
            cerr << "Failed to connect to peer" << endl;
        }
    }
    else if (message.find("/acceptconnection") != string::npos)
    {
        cout << "Peer accepted! ";
    }
    else if (message == "/declined" || message == "/declined\n")
    {
        cout << "Connection declined by the peer." << endl;
        if (listeningSockFD != -1)
        {
            close(listeningSockFD);
            listeningSockFD = -1;
        }
    }
    else if (message.find("Located") != string::npos && message.find("waiting") != string::npos)
    {
        cout << message << flush;
    }
    else
    {
        cout << "Server: " << message << flush;
    }
}

void sendFile(const string& filePath)
{
    FILE* file = fopen(filePath.c_str(), "rb");
    if (!file)
    {
        cerr << "Error: Could not open file " << filePath << endl;
        string errorMsg = "ERROR File not found\n";
        send(peerSockFD, errorMsg.c_str(), errorMsg.length(), 0);
        return;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    rewind(file);

    // Extract just the filename (not full path)
    string filename = filePath;
    size_t lastSlash = filePath.find_last_of("/\\");
    if (lastSlash != string::npos)
    {
        filename = filePath.substr(lastSlash + 1);
    }

    // Send file header: FILE filename size\n
    string header = "FILE " + filename + " " + to_string(fileSize) + "\n";
    if (send(peerSockFD, header.c_str(), header.length(), 0) == -1)
    {
        perror("send header");
        fclose(file);
        return;
    }

    cout << "\x1b[33mSending file: " << filename << " (" << fileSize << " bytes)\x1b[0m" << endl;

    // Send file data in chunks
    char buffer[4096];
    size_t totalSent = 0;
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
        size_t bytesSent = 0;
        while (bytesSent < bytesRead)
        {
            ssize_t n = send(peerSockFD, buffer + bytesSent, bytesRead - bytesSent, 0);
            if (n == -1)
            {
                perror("send file data");
                fclose(file);
                return;
            }
            bytesSent += n;
        }
        totalSent += bytesRead;
    }

    fclose(file);
    cout << "\x1b[33mFile sent successfully: " << totalSent << " bytes\x1b[0m" << endl;
}

void handlePeerMessage(const string &message)
{
    if (message.substr(0, 4) == "FILE")
    {
        // Parse: FILE filename size\n
        size_t firstSpace = message.find(' ');
        size_t secondSpace = message.find(' ', firstSpace + 1);
        
        if (firstSpace == string::npos || secondSpace == string::npos)
        {
            cerr << "Invalid FILE header" << endl;
            return;
        }

        receivingFileName = message.substr(firstSpace + 1, secondSpace - firstSpace - 1);
        string sizeStr = message.substr(secondSpace + 1);
        expectedFileSize = stoul(sizeStr);
        receivedFileSize = 0;

        // Create downloads directory if it doesn't exist
        mkdir("downloads", 0755);

        string savePath = "downloads/" + receivingFileName;
        receivingFile = fopen(savePath.c_str(), "wb");
        
        if (!receivingFile)
        {
            perror("fopen for receiving file");
            return;
        }

        recvState = RECEIVING_FILE;
        cout << "\x1b[36mReceiving file: " << receivingFileName << " (" << expectedFileSize << " bytes)\x1b[0m" << endl;
    }
    else if (message.substr(0, 5) == "ERROR")
    {
        cout << "\x1b[31mPeer: " << message.substr(6) << "\x1b[0m" << flush;
    }
    else if (message.substr(0, 9) == "/download")
    {
        string filePath = message.substr(10);
        // Remove trailing newline if present
        if (!filePath.empty() && filePath.back() == '\n')
        {
            filePath.pop_back();
        }

        bool found = false;
        for (const string& queuedFile : fileQueue)
        {
            if (queuedFile == filePath)
            {
                sendFile(filePath);
                found = true;
                break;
            }
        }

        if (!found)
        {
            cout << "\x1b[31mRequested file not in upload queue: " << filePath << "\x1b[0m" << endl;
            string errorMsg = "ERROR File not in queue\n";
            send(peerSockFD, errorMsg.c_str(), errorMsg.length(), 0);
        }
    }
    else if (message.substr(0, 6) == "/files")
    {
        string response = "";
        for (const string& filePath : fileQueue)
        {
            response += filePath + "\t";
        }
        response += "\n";

        if (send(peerSockFD, response.c_str(), response.length(), 0) == -1)
        {
            perror("send to peer");
        }
    }
    else
    {
        cout << "\x1b[32mPeer:" << message << "\x1b[0m" << flush;
    }
}

void handleInput()
{
    string stdinBuffer = "";
    char buf[256];
    int numbytes = read(STDIN_FILENO, buf, sizeof buf - 1);
    if (numbytes <= 0)
    {
        cout << "Exiting..." << endl;
        return;
    }

    buf[numbytes] = '\0';
    stdinBuffer += string(buf);

    size_t pos;
    while ((pos = stdinBuffer.find('\n')) != string::npos)
    {
        string line = stdinBuffer.substr(0, pos);
        stdinBuffer.erase(0, pos + 1);

        if (line.substr(0, 8) == "/connect")
        {
            if (listeningSockFD == -1)
            {
                listeningSockFD = createListeningSocket("4000");
                if (listeningSockFD == -1)
                {
                    cerr << "Failed to create listening socket" << endl;
                    continue;
                }
            }
        }
        else if (line.substr(0, 7) == "/upload")
        {
            string filePath = line.substr(8);
            
            // Check if file exists
            FILE* testFile = fopen(filePath.c_str(), "rb");
            if (!testFile)
            {
                cout << "\x1b[31mError: File not found: " << filePath << "\x1b[0m" << endl;
                continue;
            }
            fclose(testFile);
            
            cout << "\x1b[34;47mQueued file for upload: " << filePath << "\x1b[0m" << endl;
            fileQueue.push_back(filePath);
            continue;
        }

        line += "\n";
        if (peerSockFD != -1)
        {
            if (send(peerSockFD, line.c_str(), line.length(), 0) == -1)
            {
                perror("send to peer");
                close(peerSockFD);
                peerSockFD = -1;
            }
        }
        else if (serverSockFD != -1)
        {
            if (send(serverSockFD, line.c_str(), line.length(), 0) == -1)
            {
                perror("send to server");
                close(serverSockFD);
                serverSockFD = -1;
            }
        }
    }
}

void runClient(const string &username)
{
    struct pollfd fds[4];
    int nfds = 0;

    fds[nfds].fd = STDIN_FILENO;
    fds[nfds].events = POLLIN;
    nfds++;

    fds[nfds].fd = serverSockFD;
    fds[nfds].events = POLLIN;
    nfds++;

    if (send(serverSockFD, username.c_str(), username.length(), 0) == -1)
    {
        perror("send username");
        return;
    }

    cout << "------- Enter messages and send with enter -------" << endl;

    string stdinBuffer = "";
    string serverBuffer = "";
    string peerBuffer = "";

    while (true)
    {
        nfds = 0;

        fds[nfds].fd = STDIN_FILENO;
        fds[nfds].events = POLLIN;
        nfds++;

        if (serverSockFD != -1)
        {
            fds[nfds].fd = serverSockFD;
            fds[nfds].events = POLLIN;
            nfds++;
        }

        if (listeningSockFD != -1)
        {
            fds[nfds].fd = listeningSockFD;
            fds[nfds].events = POLLIN;
            nfds++;
        }

        if (peerSockFD != -1)
        {
            fds[nfds].fd = peerSockFD;
            fds[nfds].events = POLLIN;
            nfds++;
        }

        int poll_count = poll(fds, nfds, -1);

        if (poll_count == -1)
        {
            perror("poll");
            break;
        }

        for (int i = 0; i < nfds; i++)
        {
            if (!(fds[i].revents & POLLIN))
            {
                continue;
            }

            if (fds[i].fd == STDIN_FILENO)
            {
                handleInput();
            }
            else if (fds[i].fd == serverSockFD)
            {
                char buf[256];
                int numbytes = recv(serverSockFD, buf, sizeof buf - 1, 0);

                if (numbytes <= 0)
                {
                    if (numbytes == 0)
                    {
                        cout << "Server disconnected" << endl;
                    }
                    else
                    {
                        perror("recv from server");
                    }
                    close(serverSockFD);
                    serverSockFD = -1;
                    continue;
                }

                buf[numbytes] = '\0';
                serverBuffer += string(buf);

                handleServerMessage(serverBuffer);
                serverBuffer = "";
            }
            else if (fds[i].fd == listeningSockFD)
            {
                acceptPeerConnection();
            }
            else if (fds[i].fd == peerSockFD)
            {
                char buf[4096];
                int numbytes = recv(peerSockFD, buf, sizeof buf, 0);

                if (numbytes <= 0)
                {
                    if (numbytes == 0)
                    {
                        cout << "Peer disconnected" << endl;
                    }
                    else
                    {
                        perror("recv from peer");
                    }
                    close(peerSockFD);
                    peerSockFD = -1;
                    
                    // Clean up file receiving state if interrupted
                    if (receivingFile)
                    {
                        fclose(receivingFile);
                        receivingFile = nullptr;
                        recvState = TEXT_MODE;
                    }
                    continue;
                }

                if (recvState == RECEIVING_FILE)
                {
                    // Write binary data to file
                    size_t toWrite = min((size_t)numbytes, expectedFileSize - receivedFileSize);
                    fwrite(buf, 1, toWrite, receivingFile);
                    receivedFileSize += toWrite;

                    // Check if file is complete
                    if (receivedFileSize >= expectedFileSize)
                    {
                        fclose(receivingFile);
                        receivingFile = nullptr;
                        recvState = TEXT_MODE;
                        
                        cout << "\x1b[36mFile received successfully: downloads/" << receivingFileName 
                             << " (" << receivedFileSize << " bytes)\x1b[0m" << endl;

                        // If there's leftover data, add it to text buffer
                        if (toWrite < (size_t)numbytes)
                        {
                            peerBuffer += string(buf + toWrite, numbytes - toWrite);
                        }
                    }
                }
                else
                {
                    // Text mode - process line by line
                    peerBuffer += string(buf, numbytes);

                    size_t pos;
                    while ((pos = peerBuffer.find('\n')) != string::npos)
                    {
                        string message = peerBuffer.substr(0, pos);
                        peerBuffer.erase(0, pos + 1);

                        if (!message.empty())
                        {
                            handlePeerMessage(message + "\n");
                        }
                    }
                }
            }
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        cerr << "usage: client username" << endl;
        exit(1);
    }

    string username = argv[1];
    serverSockFD = connectToSocket("127.0.0.1", "3490");

    if (serverSockFD == -1)
    {
        cerr << "Failed to connect to server" << endl;
        return 1;
    }

    runClient(username);

    // Cleanup
    if (receivingFile)
        fclose(receivingFile);
    if (serverSockFD != -1)
        close(serverSockFD);
    if (listeningSockFD != -1)
        close(listeningSockFD);
    if (peerSockFD != -1)
        close(peerSockFD);

    return 0;
}