#include "ClientList.cpp"
#include "Server.cpp"

int main(void) {
    ClientList clientList;
    Server server(clientList);
    server.run();
    return 0;
}