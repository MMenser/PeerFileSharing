#include "ClientList.cpp"
#include "Server.cpp"

int main() {
    ClientList clientList;
    Server server(clientList);
    server.run();
    return 0;
}