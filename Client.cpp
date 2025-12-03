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
#include <chrono>
#include <iomanip>
#include "SSLHelper.cpp"
using namespace std;
using namespace std::chrono;

int listeningSockFD = -1;
int serverSockFD = -1;
int peerSockFD = -1;
vector<string> fileQueue;

// File receiving state
enum ReceiveState
{
    TEXT_MODE,
    RECEIVING_FILE
};
ReceiveState recvState = TEXT_MODE;
FILE *receivingFile = nullptr;
size_t expectedFileSize = 0;
size_t receivedFileSize = 0;
string receivingFileName = "";
SSL *peerSSL = nullptr;

// Transfer metrics
steady_clock::time_point transferStartTime;
steady_clock::time_point lastProgressUpdate;

// Helper function to format bytes
string formatBytes(size_t bytes)
{
    const char* units[] = {"B", "KB", "MB", "GB"};
    int unitIndex = 0;
    double size = bytes;
    
    while (size >= 1024 && unitIndex < 3)
    {
        size /= 1024;
        unitIndex++;
    }
    
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%.2f %s", size, units[unitIndex]);
    return string(buffer);
}

// Helper function to format speed
string formatSpeed(double bytesPerSec)
{
    return formatBytes((size_t)bytesPerSec) + "/s";
}

// Helper function to format time
string formatTime(int seconds)
{
    if (seconds < 60)
        return to_string(seconds) + "s";
    else if (seconds < 3600)
        return to_string(seconds / 60) + "m " + to_string(seconds % 60) + "s";
    else
        return to_string(seconds / 3600) + "h " + to_string((seconds % 3600) / 60) + "m";
}

// Draw progress bar
void drawProgressBar(size_t current, size_t total, double speed)
{
    int barWidth = 40;
    float progress = (float)current / total;
    int pos = barWidth * progress;
    
    double elapsedSec = duration_cast<milliseconds>(steady_clock::now() - transferStartTime).count() / 1000.0;
    int etaSeconds = (speed > 0) ? (int)((total - current) / speed) : 0;
    
    cout << "\r\x1b[36m[";
    for (int i = 0; i < barWidth; i++)
    {
        if (i < pos) cout << "=";
        else if (i == pos) cout << ">";
        else cout << " ";
    }
    cout << "] " << fixed << setprecision(1) << (progress * 100.0) << "% "
         << "(" << formatBytes(current) << "/" << formatBytes(total) << ") "
         << formatSpeed(speed) << " ETA: " << formatTime(etaSeconds)
         << "\x1b[0m" << flush;
}

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

    cout << "\x1b[36m" << "Peer listening on port " << port << "\x1b[0m" << endl;
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

void acceptPeerConnection(SSLHelper &ssl)
{
    if (listeningSockFD == -1)
    {
        cerr << "No listening socket available" << endl;
        return;
    }

    struct sockaddr_storage their_addr;
    socklen_t sin_size = sizeof their_addr;

    cout << "\x1b[36m" << "Waiting for peer to connect..." << "\x1b[0m" << endl;
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

    peerSSL = ssl.tls_server_handshake(peerSockFD);
    if (!peerSSL)
    {
        cerr << "TLS server handshake failed." << endl;
        close(peerSockFD);
        peerSockFD = -1;
        return;
    }

    cout << "\x1b[36m" << "Peer connected and TLS handshake successful from " << s << "\x1b[0m" << endl;

    close(listeningSockFD);
    listeningSockFD = -1;

    closeServerConnection();
}

void handleServerMessage(const string &message, SSLHelper &ssl)
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

        cout << "\x1b[36m" << "Connecting to peer at " << peerIP << "\x1b[0m" << endl;
        closeServerConnection();

        peerSockFD = connectToSocket(peerIP.c_str(), "4000");
        if (peerSockFD != -1)
        {
            SSL *peerSSL = ssl.tls_client_handshake(peerSockFD);
            if (!peerSSL)
            {
                cerr << "TLS client handshake failed." << endl;
                close(peerSockFD);
                peerSockFD = -1;
                return;
            }
            cout << "\x1b[36m" << "Connected to peer and TLS handshake successful!" << "\x1b[0m" << endl;
        }
        else
        {
            cerr << "Failed to connect to peer" << endl;
        }
    }
    else if (message.find("/acceptconnection") != string::npos)
    {
        cout << "\x1b[36m" << "Peer accepted!" << "\x1b[0m" << endl;
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
        cout << "Server: " << message << endl;
    }
}

void sendFile(const string &filePath, SSLHelper &ssl)
{
    FILE *file = fopen(filePath.c_str(), "rb");
    if (!file) {
        cerr << "Error: Could not open file " << filePath << endl;
        string errorMsg = "ERROR File not found\n";
        ssl.ssl_send(errorMsg.c_str(), errorMsg.length(), peerSockFD);
        return;
    }

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    rewind(file);

    string filename = filePath;
    size_t lastSlash = filePath.find_last_of("/\\");
    if (lastSlash != string::npos)
    {
        filename = filePath.substr(lastSlash + 1);
    }

    string header = "FILE " + filename + " " + to_string(fileSize) + "\n";
    if (ssl.ssl_send(header.c_str(), header.length(), peerSockFD) == -1)
    {
        perror("send header");
        fclose(file);
        return;
    }

    cout << "\x1b[33mSending file: " << filename << " (" << formatBytes(fileSize) << ")\x1b[0m" << endl;

    // Start transfer metrics
    auto startTime = steady_clock::now();
    auto lastUpdate = startTime;
    
    char buffer[4096];
    size_t totalSent = 0;
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
        size_t bytesSent = 0;
        while (bytesSent < bytesRead)
        {
            ssize_t n = ssl.ssl_send(buffer + bytesSent, bytesRead - bytesSent, peerSockFD);
            if (n == -1)
            {
                perror("send file data");
                fclose(file);
                return;
            }
            bytesSent += n;
        }
        totalSent += bytesRead;

        // Update progress every 100ms
        auto now = steady_clock::now();
        auto elapsed = duration_cast<milliseconds>(now - lastUpdate).count();
        if (elapsed >= 100 || totalSent == (size_t)fileSize)
        {
            double elapsedSec = duration_cast<milliseconds>(now - startTime).count() / 1000.0;
            double speed = (elapsedSec > 0) ? (totalSent / elapsedSec) : 0;
            drawProgressBar(totalSent, fileSize, speed);
            lastUpdate = now;
        }
    }

    auto endTime = steady_clock::now();
    double totalTime = duration_cast<milliseconds>(endTime - startTime).count();
    double avgSpeed = totalTime > 0 ? totalSent / totalTime : 0;

    cout << endl << "\x1b[33mFile sent successfully!" << endl
         << "  Size: " << formatBytes(totalSent) << endl
         << "  Time: " << fixed << setprecision(2) << totalTime << "ms" << endl
         << "  Avg Speed: " << formatSpeed(avgSpeed) << "\x1b[0m" << endl;

    fclose(file);
}

void handlePeerMessage(const string &message, SSLHelper &ssl, const string &username)
{
    if (message.substr(0, 4) == "FILE")
    {
        size_t firstSpace = message.find(' ');
        size_t secondSpace = message.find(' ', firstSpace + 1);
        mkdir((username + "/downloads").c_str(), 0755);

        if (firstSpace == string::npos || secondSpace == string::npos)
        {
            cerr << "Invalid FILE header" << endl;
            return;
        }

        receivingFileName = message.substr(firstSpace + 1, secondSpace - firstSpace - 1);
        string sizeStr = message.substr(secondSpace + 1);
        expectedFileSize = stoul(sizeStr);
        receivedFileSize = 0;
        
        string savePath = username + "/downloads/" + receivingFileName;
        receivingFile = fopen(savePath.c_str(), "wb");

        if (!receivingFile)
        {
            perror("fopen for receiving file");
            return;
        }

        recvState = RECEIVING_FILE;
        transferStartTime = steady_clock::now();
        lastProgressUpdate = transferStartTime;
        
        cout << "\x1b[36mReceiving file: " << receivingFileName << " (" << formatBytes(expectedFileSize) << ")\x1b[0m" << endl;
    }
    else if (message.substr(0, 5) == "ERROR")
    {
        cout << "\x1b[31mPeer: " << message.substr(6) << "\x1b[0m" << flush;
    }
    else if (message.substr(0, 9) == "/download")
    {
        string filePath = message.substr(10);
        if (!filePath.empty() && filePath.back() == '\n')
        {
            filePath.pop_back();
        }

        bool found = false;
        for (const string &queuedFile : fileQueue)
        {
            if (queuedFile == filePath)
            {
                sendFile(filePath, ssl);
                found = true;
                break;
            }
        }

        if (!found)
        {
            cout << "\x1b[31mRequested file not in upload queue: " << filePath << "\x1b[0m" << endl;
            string errorMsg = "ERROR File not in queue\n";
            ssl.ssl_send(errorMsg.c_str(), errorMsg.length(), peerSockFD);
        }
    }
    else if (message.substr(0, 6) == "/files")
    {
        string response = "";
        if (fileQueue.empty())
        {
            response = "No files uploaded.\n";
        }
        else
        {
            for (const string &filePath : fileQueue)
            {
                response += filePath + "\t";
            }
        }

        response += "\n";

        if (ssl.ssl_send(response.c_str(), response.length(), peerSockFD) == -1)
        {
            perror("send to peer");
        }
    }
    else
    {
        cout << "\x1b[32mPeer:" << message << "\x1b[0m" << flush;
    }
}

void handleInput(SSLHelper &ssl)
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

            FILE *testFile = fopen(filePath.c_str(), "rb");
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
            if (ssl.ssl_send(line.c_str(), line.length(), peerSockFD) == -1)
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

    SSLHelper ssl(username);
    ssl.init_openssl();
    SSL_CTX *ssl_context = ssl.create_context();
    if (!ssl_context)
    {
        cerr << "Failed to create SSL context. Exiting." << endl;
        return;
    }

    string key_path = username + "/server.key";
    string cert_path = username + "/server.crt";
    if (!ssl.load_certificates(ssl_context, cert_path.c_str(), key_path.c_str(), nullptr)) 
    {
        cerr << "Failed to load certificates. Exiting." << endl;
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
                handleInput(ssl);
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

                handleServerMessage(serverBuffer, ssl);
                serverBuffer = "";
            }
            else if (fds[i].fd == listeningSockFD)
            {
                acceptPeerConnection(ssl);
                break;
            }
            else if (fds[i].fd == peerSockFD)
            {
                char buf[4096];
                int numbytes = ssl.ssl_recv(buf, sizeof buf, peerSockFD);

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

                    if (receivingFile)
                    {
                        fclose(receivingFile);
                        receivingFile = nullptr;
                        recvState = TEXT_MODE;
                    }

                    if(peerSSL) {
                        SSL_free(peerSSL);
                        peerSSL = nullptr;
                    }
                    continue;
                }

                if (recvState == RECEIVING_FILE)
                {
                    size_t toWrite = min((size_t)numbytes, expectedFileSize - receivedFileSize);
                    fwrite(buf, 1, toWrite, receivingFile);
                    receivedFileSize += toWrite;

                    // Update progress every 100ms
                    auto now = steady_clock::now();
                    auto elapsed = duration_cast<milliseconds>(now - lastProgressUpdate).count();
                    if (elapsed >= 100 || receivedFileSize >= expectedFileSize)
                    {
                        double elapsedSec = duration_cast<milliseconds>(now - transferStartTime).count() / 1000.0;
                        double speed = (elapsedSec > 0) ? (receivedFileSize / elapsedSec) : 0;
                        drawProgressBar(receivedFileSize, expectedFileSize, speed);
                        lastProgressUpdate = now;
                    }

                    if (receivedFileSize >= expectedFileSize)
                    {
                        fclose(receivingFile);
                        receivingFile = nullptr;
                        recvState = TEXT_MODE;

                        auto endTime = steady_clock::now();
                        double totalTime = duration_cast<milliseconds>(endTime - transferStartTime).count();
                        double avgSpeed = totalTime > 0 ? receivedFileSize / totalTime : 0;

                        cout << endl << "\x1b[36m File received successfully!" << endl
                             << "  Saved to: " << username << "/downloads/" << receivingFileName << endl
                             << "  Size: " << formatBytes(receivedFileSize) << endl
                             << "  Time: " << fixed << setprecision(2) << totalTime << "ms" << endl
                             << "  Avg Speed: " << formatSpeed(avgSpeed) << "\x1b[0m" << endl;

                        if (toWrite < (size_t)numbytes)
                        {
                            peerBuffer += string(buf + toWrite, numbytes - toWrite);
                        }
                    }
                    continue;
                }
                else
                {
                    peerBuffer += string(buf, numbytes);

                    size_t pos;
                    while ((pos = peerBuffer.find('\n')) != string::npos)
                    {
                        string message = peerBuffer.substr(0, pos);
                        peerBuffer.erase(0, pos + 1);

                        if (!message.empty())
                        {
                            handlePeerMessage(message + "\n", ssl, username);
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