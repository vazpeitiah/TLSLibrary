#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>

#include "pq.h"

#define PORT 9999 /* default port to connecto to server */
#define FCLIENT 0 /* Flag value client */

extern unsigned long long cyclesAES;    /* Cycles count var for AES */
extern unsigned long long cyclesKY;     /* Cycles count var for Kyber */
extern unsigned long long cyclesDil;    /* Cycles count var for Dilithium */

//argv[1] = dilithium || argv[1] = newhope
//argv[2] = 0 no sign || argv[2] = 1 server cert verify || argv[2] = 2 both verify

int main(int argc, char const *argv[]) {
    int sock = 0;                   /* Socket fd for client*/
    struct sockaddr_in serv_addr;   /* For assign server address */

    char opt1[NSB]; /* Assign argv[1] */
    int opt2;       /* Save integer value of argv[2] */

    if (argc < 2) {
        printf("usage: %s <opts1> <opts2>\n", argv[0]);
        return -1;
    }

    memcpy(opt1, argv[1], strlen(argv[1])); /* Copy argv[1] in opt1 */
    opt2 = atoi(argv[2]);                   /* Cast argv[2] to integer */

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT); /* Assingn PORT to address server */

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    send(sock, opt1, sizeof(opt1), 0);          /* Send opt1 to server as string */
    send(sock, argv[2], sizeof(argv[2]), 0);    /* Send opt2 to server as string */

    unsigned long long initCycles = rdtsc();
    TLS(sock, opt1, opt2, FCLIENT);                         /* Init pq functions */      
    unsigned long long totalCycles = rdtsc() - initCycles;

    int cs = shutdown(sock, 2); /* Shutdown client socket */

    switch (opt2) { /* Append register to log file */
        default:
        case 0:
            mfiles("./Classic-No-Dilitium", cyclesDil, cyclesKY, cyclesAES, totalCycles);
            break;
        case 1:
            mfiles("./Classic-Single-Dilitium", cyclesDil, cyclesKY, cyclesAES, totalCycles);
            break;
        case 2:
            mfiles("./Classic-Double-Dilitium", cyclesDil, cyclesKY, cyclesAES, totalCycles);
            break;
    }
    
    return 0;
}