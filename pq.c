#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/time.h>
#include <string.h>
#include <stdio.h>

#include "kyber/ref/api.h"
#include "kyber/ref/fips202.h"

#include "params.h"

#include "dilithium1aes/randombytes.h"
#include "dilithium1aes/params.h"
#include "dilithium1aes/sign.h"

#include "opensslaes.h"
#include "pq.h"
#include "vault.h"

unsigned long long cyclesAES;
unsigned long long cyclesNH;
unsigned long long cyclesDil;

void recv_timeout(int socket, unsigned char *c, double timeout)
{
    int size_recv, total_size = 0;
    struct timeval begin, now;
    char chunk[CHUNK_SIZE];
    double timediff;
    int flags;

    // Save the existing flags
    flags = fcntl(socket, F_GETFL, 0);
    //make socket non blocking
    fcntl(socket, F_SETFL, O_NONBLOCK);

    //beginning time
    gettimeofday(&begin, NULL);

    while (1)
    {
        gettimeofday(&now, NULL);

        //time elapsed in miliseconds
        timediff = ((now.tv_sec - begin.tv_sec) * 1e6 + (now.tv_usec - begin.tv_usec))/1000;

        //if you got some data, then break after timeout
        if (timediff > timeout)
        {
            break;
        }
        else if (timediff > timeout*2)//if you got no data at all, wait a little longer, twice the timeout
        {
            break;
        }

        memset(chunk ,0 , CHUNK_SIZE);  //clear the variable

        if((size_recv =  recv(socket, chunk, CHUNK_SIZE, 0) ) < 0)
        {
            //if nothing was received then we want to wait a little before trying again, 500 milliseconds
            usleep(500000);
        }
        else
        {
            memcpy(c + total_size, chunk, CHUNK_SIZE);
            total_size += size_recv;
            //reset beginning time
            gettimeofday(&begin, NULL);
        }
    }

    /* Clear the blocking flag. */
    flags &= ~O_NONBLOCK;
    //make socket blocking
    fcntl(socket, F_SETFL, flags);
}

void printBstr(char *S, unsigned char *A, unsigned long long len)
{
    unsigned long long  i;

    printf("%s", S);

    for ( i=0; i<len; i++ )
        printf("%02X", A[i]);

    if ( len == 0 )
        printf("00");

    printf("\n");
}

void fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long len)
{
    unsigned long long  i;

    fprintf(fp, "%s", S);

    for ( i=0; i<len; i++ )
        fprintf(fp, "%02X", A[i]);

    if ( len == 0 )
        fprintf(fp, "00");

    fprintf(fp, "\n");
}

void mfiles (char *filename, unsigned long long dilithium, unsigned long long newhope, unsigned long long aes, unsigned long long total)
{
    FILE *fp = fopen(filename, "a");
    if(fp)
    {
        fprintf(fp,"%llu,%llu,%llu,%llu\n", dilithium, newhope, aes, total); //print file
    }
    fclose(fp);
}

/****** -> Dilithium ******/
// opt = 1: KeyGen, Sign; opt = 0: Verification
int dilithium1(int sock, int opt)
{
    int ret, j;
    int flag = 0;
    unsigned char buffer[NBYTES];
    unsigned long long mlen, smlen;
    unsigned char m[MLEN];
    unsigned char m2[MLEN + CRYPTO_BYTES_DILI];
    unsigned char sm[MLEN + CRYPTO_BYTES_DILI];
    unsigned char pk[CRYPTO_PUBLICKEYBYTES_DILI];
    unsigned char sk[CRYPTO_SECRETKEYBYTES_DILI];

    unsigned char stream[CRYPTO_PUBLICKEYBYTES_DILI+MLEN+CRYPTO_BYTES_DILI+MLEN];

    bzero(buffer, NBYTES);
    bzero(stream, CRYPTO_PUBLICKEYBYTES_DILI+MLEN+CRYPTO_BYTES_DILI+MLEN);
    bzero(m, MLEN);
    bzero(m2, MLEN + CRYPTO_BYTES_DILI);
    bzero(sm, MLEN + CRYPTO_BYTES_DILI);
    bzero(pk, CRYPTO_PUBLICKEYBYTES_DILI);

    // KeyGen and Sign
    // opt = 1 | send pk and cert with sign
    if (opt)
    {
        randombytes(m, MLEN);

        ret = crypto_sign_keypair(pk, sk); //KeyGen
        send(sock, &ret, sizeof(ret), 0);
        if(ret)
        {
            flag = 1;
            strcpy((char *)buffer, "Generation the public/private keypair failed (Dilithium)");
            printf("ERROR: %s\n", buffer);
            send(sock, buffer, strlen((char *)buffer), 0);
            return flag;
        }

        ret = crypto_sign(sm, &smlen, m, MLEN, sk); //Sign
        send(sock, &ret, sizeof(ret), 0);
        if(ret)
        {
            flag = 1;
            strcpy((char *)buffer, "Sign failed (Dilithium)");
            printf("ERROR: %s\n", buffer);
            send(sock, buffer, strlen((char *)buffer), 0);
            return flag;
        }

        send(sock, &smlen, sizeof(smlen), 0);

        memcpy(stream, pk, CRYPTO_PUBLICKEYBYTES_DILI);
        memcpy(&stream[CRYPTO_PUBLICKEYBYTES_DILI], sm, MLEN + CRYPTO_BYTES_DILI);
        memcpy(&stream[CRYPTO_PUBLICKEYBYTES_DILI+MLEN+CRYPTO_BYTES_DILI], m, MLEN);

        send(sock, stream, CRYPTO_PUBLICKEYBYTES_DILI+MLEN+CRYPTO_BYTES_DILI+MLEN, 0);

        ret = read(sock, &flag, sizeof(flag));

        if (flag)
        {
            ret = read(sock, buffer, NBYTES);
            buffer[ret] = '\0';
            printf("ERROR: %s\n", buffer);
        }
    }
    else // Verification
    {
        // Keypair
        ret = read(sock, &flag, sizeof(flag));
        if (flag)
        {
            ret = read(sock, buffer, NBYTES);
            buffer[ret] = '\0';
            printf("ERROR: %s\n", buffer);
            return flag;
        }

        // Sign
        ret = read(sock, &flag, sizeof(flag));
        if (flag)
        {
            ret = read(sock, buffer, NBYTES);
            buffer[ret] = '\0';
            printf("ERROR: %s\n", buffer);
            return flag;
        }

        ret = read(sock, &smlen, sizeof(smlen));
        recv_timeout(sock, stream, TW);

        memcpy(pk, stream, CRYPTO_PUBLICKEYBYTES_DILI);
        memcpy(sm, &stream[CRYPTO_PUBLICKEYBYTES_DILI], MLEN + CRYPTO_BYTES_DILI);
        memcpy(m, &stream[CRYPTO_PUBLICKEYBYTES_DILI + MLEN + CRYPTO_BYTES_DILI], MLEN);

        ret = crypto_sign_open(m2, &mlen, sm, smlen, pk); //Verification

        if(ret) {
            sprintf((char *)buffer, "Verification failed <%d>", ret);
            flag = 1;
        }
        else if(mlen != MLEN) {
            strcpy((char *)buffer, "Message lengths don't match");
            flag = 1;
        }
        else
        {
            for(j = 0; j < mlen; ++j) {
                if(m[j] != m2[j]) {
                    strcpy((char *)buffer, "Messages don't match");
                    flag = 1;
                }
            }
        }

        send(sock, &flag, sizeof(flag), 0);

        if(flag)
        {
            printf("ERROR: %s\n", buffer);
            send(sock, buffer, strlen((char *)buffer), 0);
        }
    }

    return flag;
}
/****** Dilithium <- ******/

/****** -> Kyber ******/
// opt = 1: Server; opt = 0: Client
int kyber1024(int sock, int opt, unsigned char *ss)
{
    int ret;
    int flag = 0;
    unsigned char buffer[NBYTES];
    unsigned char pk[pqcrystals_kyber1024_ref_PUBLICKEYBYTES];
    unsigned char sk[pqcrystals_kyber1024_ref_SECRETKEYBYTES];
    unsigned char ct[pqcrystals_kyber1024_ref_CIPHERTEXTBYTES];

    bzero(buffer, NBYTES);
    bzero(pk, pqcrystals_kyber1024_ref_PUBLICKEYBYTES);
    bzero(ct, pqcrystals_kyber1024_ref_CIPHERTEXTBYTES);

    //KeyGen and Desencapsulate (server)
    if (opt)
    {
        bzero(buffer, NBYTES);
        ret = pqcrystals_kyber1024_ref_keypair(pk, sk); //KeyGen

        send(sock, &ret, sizeof(ret), 0);
        if(ret)
        {
            flag = 1;
            strcpy((char *)buffer, "Generation the public/private keypair failed (Kyber)");
            printf("ERROR: %s\n", buffer);
            send(sock, buffer, strlen((char *)buffer), 0);
            return flag;
        }

        send(sock, pk, pqcrystals_kyber1024_ref_PUBLICKEYBYTES, 0);

        bzero(buffer, NBYTES);
        ret = read(sock, &flag, sizeof(flag));
        if (flag)
        {
            ret = read(sock, buffer, NBYTES);
            buffer[ret] = '\0';
            printf("ERROR: %s\n", buffer);
            return flag;
        }

        bzero(buffer, NBYTES);
        recv_timeout(sock, buffer, TW);
        memcpy(ct, buffer, pqcrystals_kyber1024_ref_CIPHERTEXTBYTES);

        ret = pqcrystals_kyber1024_ref_dec(ss, ct, sk); //Desencapsulate
        send(sock, &ret, sizeof(ret), 0);
        if (ret)
        {
            flag = 1;
            strcpy((char *)buffer, "Encapsultaion failed");
            send(sock, buffer, strlen((char *)buffer), 0);
            printf("ERROR: %d\n", ret);
            return flag;
        }
    }
    else // Encapsulate (Codigo del cliente)
    {
        bzero(pk, pqcrystals_kyber1024_ref_PUBLICKEYBYTES);
        // Keypair
        ret = read(sock, &flag, sizeof(flag));
        if (flag)
        {
            ret = read(sock, buffer, NBYTES);
            buffer[ret] = '\0';
            printf("ERROR: %s\n", buffer);
            return flag;
        }

        //ret = read(sock, pk, pqcrystals_kyber1024_ref_PUBLICKEYBYTES);
        recv_timeout(sock, pk, TW);

        ret = pqcrystals_kyber1024_ref_enc(ct, ss, pk); // Encapsulate
        send(sock, &ret, sizeof(ret), 0);
        if(ret)
        {
            flag = 1;
            strcpy((char *)buffer, "Desencapsultaion failed");
            send(sock, buffer, strlen((char *)buffer), 0);
            return flag;
        }

        send(sock, ct, sizeof(ct), 0);

        ret = read(sock, &flag, sizeof(flag));
        if (flag)
        {
            ret = read(sock, buffer, NBYTES);
            buffer[ret] = '\0';
            return flag;
        }
    }

    return flag;
}
/****** Kyber <- ******/

/****** -> AES ******/
void symmetric_enc_dec(int sock, int flag, unsigned char *k1, unsigned char *k2, unsigned char *msg) {
    int dlen, elen;
    unsigned char ciphertext[BS * 10];

    bzero(ciphertext, BS * 10);

    if (flag) { // -- Codigo del servidor --
        int cipher_len = recv(sock, ciphertext, BS * 10, 0);
        ciphertext[cipher_len] = '\0';
                                                                        
        dlen = decrypt(ciphertext, cipher_len, k1, k2, msg);    // Decrypt the ciphertext
        msg[dlen] = '\0';   //Add a NULL terminator. We are expecting printable text */
    }
    else {  // -- Codigo del cliente --
        elen = encrypt(msg, strlen((char *)msg), k1, k2, ciphertext);   // Encrypt the plaintext (key, iv)

        send(sock, ciphertext, elen, 0);
        usleep(1000000); // sleep 0.1 seg
    }
}

void safe_channel(int sock, int flag) {
    unsigned char ss[pqcrystals_kyber1024_ref_BYTES];       /* Clave compartida */
    unsigned char vault[BS];                                /* Vault concatenado en una cadena */

    bzero(ss, pqcrystals_kyber1024_ref_BYTES);
    bzero(vault, BS);

    if (flag == 0) { /* Codigo del cliente */ 
        /* Obtener vault, como cadena de texto, desde archivo de texto */
        getVaultStr((char *)vault, "valores_de_prueba/Vault105-1.txt");
        shake256(ss, pqcrystals_kyber1024_ref_BYTES, vault, BS);
        printf("Client: vault = %s\n", vault);
    }

    unsigned long long initCycles = rdtsc(); 
    if(kyber1024(sock, flag, ss)) { return; }      /* Obtener la clave compartida utilizando el KEM */

    cyclesNH = rdtsc() - initCycles;

    initCycles = rdtsc();
    symmetric_enc_dec(sock, flag, ss, ss, vault);   /* Aplica AES 256 al vault */
    cyclesAES = rdtsc() - initCycles;

    if (flag == 1) {    // Codigo del servidor
        printf("Server: vault = %s\n", vault);
    }
}

void unsafe_channel(int sock, int flag) {
    unsigned char vault[BS];                                /* Vault concatenado en una cadena */

    bzero(vault, BS);

    if (flag == 0) { /* Codigo del cliente */ 
        /* Obtener vault, como cadena de texto, desde archivo de texto */
        getVaultStr((char *)vault, "valores_de_prueba/Vault105-1.txt");
        printf("Client: vault = %s\n", vault);
        send(sock, vault, sizeof(vault), 0);
        usleep(1000000); // sleep 0.1 seg
    }

    if (flag == 1) {    // Codigo del servidor
        int len = recv(sock, &vault, sizeof(vault), 0);
        vault[len] = '\0';

        printf("Server: vault = %s\n", vault);
    }
}

/****** -> TLS ******/
/* opt2 = 0 no sign || opt2 = 1 server cert verify || opt2 = 2 both verify */
void TLS(int sock, int opt1, int opt2, int flag) {
    unsigned long long initCycles;
    if(opt1 == 1) {
        if (opt2 == 0) {                        // No sign
            cyclesDil = 0;
            safe_channel(sock, flag);
        } else if (opt2 == 1) {                 // Verificacion server cert
            initCycles = rdtsc();
            if (dilithium1(sock, flag)) {
                return;
            }
            cyclesDil = rdtsc() - initCycles;
            safe_channel(sock, flag);
        } else if (opt2 == 2) {                 // Both
            initCycles = rdtsc();
            if (dilithium1(sock, flag)) {
                return;
            }
            if (dilithium1(sock, !flag)) {
                return;
            }
            cyclesDil = rdtsc() - initCycles;
            safe_channel(sock, flag);
        }
    } else if(opt1 == 0){
        unsafe_channel(sock, flag);
    }
}