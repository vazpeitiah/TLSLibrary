#include <stdio.h> 
#include <unistd.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#include <errno.h>

#include "pq.h"

#define PORT 9999   /* Default port to bind server */
#define FSERVER 1   /* Flag value server */

int main(int argc, char const *argv[]) {
    int server_fd;                  /* Socket fd server */
    int new_socket;                 /* Socket fd clients */
    struct sockaddr_in address;     /* Server address */
    int optval = 1;
    int len;                        /* Length of value recive from clients */
    int addrlen = sizeof(address);  /* Client address */ 

    char opt1[NSB] = {0}; /* Opt1 => dilithium || kyber */
    char opt2[NSB] = {0}; /* Opt1 => 0 no sign || 1 server cert verify || 2 both verify*/
       
    // Creating socket file descriptor with tcp
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    }

    // Forcefully attaching socket to the port PORT 
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &optval, sizeof(optval))) { 
        perror("setsockopt"); 
        exit(EXIT_FAILURE); 
    }

    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( PORT );       /* Set port PORT to address server */
       
    // Forcefully attaching socket to the port PORT 
    if (bind(server_fd, (struct sockaddr *)&address,sizeof(address))<0) {
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 

    // Start to listen request from clients
    if (listen(server_fd, 3) < 0) {
        perror("listen"); 
        exit(EXIT_FAILURE); 
    }
    printf("[+] Server start lisntenig on port %d\n", PORT);

    while (1) {
        printf("[+] Esperando peticiones\n");
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address,  
                           (socklen_t*)&addrlen))<0) {
            perror("accept"); 
            exit(EXIT_FAILURE); 
        }
        printf("[+] Peticion recibida\n");

        len = recv(new_socket, &opt1, sizeof(opt1), 0); /* Recive opt1 from client */
        opt1[len] = '\0';                               /* put end of string character */

        len = recv(new_socket, &opt2, sizeof(opt2), 0); /* Recive opt2 from client */
        opt2[len] = '\0';                               /* put end of string character */

        int opt2Int = atoi(opt2);   /* Cast opt2 to integer */

        TLS(new_socket, opt1, opt2Int, FSERVER);    /* Init pq functions */

        shutdown(new_socket, 2);   /* Shutdown client socket */
        fflush(stdout);                     /* Clean output buffer */ 

        bzero(opt1, NSB);   /* Clean var opt1 */
        bzero(opt2, NSB);   /* Clean var opt2 */
    }

    return 0; 
} 