#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

int main(void) {
    struct addrinfo hints, *servinfo, *iter;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP
    hints.ai_flags = AI_PASSIVE; // use my IP

    int rv = 0;
    rv = getaddrinfo(NULL, "3490", &hints, &servinfo);
    if (rv != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    }

    // 

    for (iter = servinfo; iter != NULL; iter = iter->ai_next) {
        char ipstr[INET6_ADDRSTRLEN];
        inet_ntop(iter->ai_family, 
                  &(((struct sockaddr_in *)iter->ai_addr)->sin_addr), 
                  ipstr, sizeof ipstr);
        printf("IP Address: %s\n", ipstr);
    }

    if (iter == NULL) {
    // looped off the end of the list with no connection
    fprintf(stderr, "failed to connect\n");
    exit(2);
}

    return 0;
}