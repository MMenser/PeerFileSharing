#ifndef CLIENTLIST_H
#define CLIENTLIST_H

#include <string>
#include <iostream>
#include <cstring>
#include <sys/mman.h>
#include <arpa/inet.h>

using namespace std;
const int MAX_CLIENTS = 10;

struct ClientInfo {
    char username[50];
    int socket_fd;
    bool active;
    char ip[INET_ADDRSTRLEN]; // store client IP
};


class ClientList {
private:
    ClientInfo *clients;
    int *availablePorts; // Ports available for p2p connections
    int *takenPorts; // Ports currently in use for p2p connections
    int *count;

public:
    ClientList() {
        // Create shared memory that persists across fork()
        clients = (ClientInfo*)mmap(NULL, sizeof(ClientInfo) * MAX_CLIENTS,
                                     PROT_READ | PROT_WRITE,
                                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);

        count = (int*)mmap(NULL, sizeof(int),
                           PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        
        memset(clients, 0, sizeof(ClientInfo) * MAX_CLIENTS);
        *count = 0;

        availablePorts = (int*)mmap(NULL, sizeof(int) * MAX_CLIENTS,
                                    PROT_READ | PROT_WRITE,
                                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        takenPorts = (int*)mmap(NULL, sizeof(int) * MAX_CLIENTS,
                                PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_ANONYMOUS, -1, 0);

        for (int i = 0; i < MAX_CLIENTS / 2; i++) { // Only need 5 ports for 5 pairs of clients
            availablePorts[i] = 4000 + i; // Example port range for p2p
        }
    }
    
    ~ClientList() {
        munmap(clients, sizeof(ClientInfo) * MAX_CLIENTS);
        munmap(count, sizeof(int));
        munmap(availablePorts, sizeof(int) * MAX_CLIENTS);
        munmap(takenPorts, sizeof(int) * MAX_CLIENTS);
    }
    
    void add(const std::string& username, int socket_fd, const std::string& ip) {
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!clients[i].active) {
                strncpy(clients[i].username, username.c_str(), 49);
                clients[i].username[49] = '\0';
                clients[i].socket_fd = socket_fd;
                clients[i].active = true;
                strncpy(clients[i].ip, ip.c_str(), INET_ADDRSTRLEN - 1);
                clients[i].ip[INET_ADDRSTRLEN - 1] = '\0';
                (*count)++;
                break;
            }
        }
    }

    void remove(int socket_fd) {
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active && clients[i].socket_fd == socket_fd) {
                clients[i].active = false;
                (*count)--;
                break;
            }
        }
    }

    char* findUserIP(string username) {
        for (int i = 0; i < *count; i++) {
            if (clients[i].active && username == clients[i].username) {
                return clients[i].ip;
            }
        }
        return nullptr;
    }

    int findUserSockFD(string username) {
        for (int i = 0; i < *count; i++) {
            if (clients[i].active && username == clients[i].username) {
                return clients[i].socket_fd;
            }
        }
        return -1;
    }
    
    std::string getList() const {
        std::string list = "Connected users:\n";
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active) {
                list += "  - " + std::string(clients[i].username) + "\n";
            }
        }
        return list;
    }
    
    int getCount() const {
        return *count;
    }
};

#endif // CLIENTLIST_H