#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "params.h"

#include "dilithium1aes/randombytes.h"
#include "dilithium1aes/params.h"
#include "dilithium1aes/sign.h"

#include "kyber/apiky.h"
#include "kyber/fips202ky.h"
#include "kyber/kem.h"
#include "kyber/rngky.h"
#include <errno.h>


#include "opensslaes.h"
#include "pq.h"

unsigned long long cyclesAES;
unsigned long long cyclesKY;
unsigned long long cyclesDil;

int **readmatrix(size_t *rows, size_t *cols, const char *filename)
{
    if(rows == NULL || cols == NULL || filename == NULL)
        return NULL;

    *rows = 0;
    *cols = 0;

    FILE *fp = fopen(filename, "r");

    if(fp == NULL)
    {
        fprintf(stderr, "could not open %s: %s\n", filename, strerror(errno));
        return NULL;
    }

    int **matrix = NULL, **tmp;

    char line[1024];

    while(fgets(line, sizeof line, fp))
    {
        if(*cols == 0)
        {
            // determine the size of the columns based on
            // the first row
            char *scan = line;
            int dummy;
            int offset = 0;
            while(sscanf(scan, "%d%n", &dummy, &offset) == 1)
            {
                scan += offset;
                (*cols)++;
            }
        }

        tmp = realloc(matrix, (*rows + 1) * sizeof *matrix);

        if(tmp == NULL)
        {
            fclose(fp);
            return matrix; // return all you've parsed so far
        }

        matrix = tmp;

        matrix[*rows] = calloc(*cols, sizeof *matrix[*rows]);

        if(matrix[*rows] == NULL)
        {
            fclose(fp);
            if(*rows == 0) // failed in the first row, free everything
            {
                fclose(fp);
                free(matrix);
                return NULL;
            }

            return matrix; // return all you've parsed so far
        }

        int offset = 0;
        char *scan = line;
        for(size_t j = 0; j < *cols; ++j)
        {
            if(sscanf(scan, "%d%n", matrix[*rows] + j, &offset) == 1)
                scan += offset;
            else
                matrix[*rows][j] = 0; // could not read, set cell to 0
        }

        // incrementing rows
        (*rows)++;
    }

    fclose(fp);

    return matrix;
}

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
            strcpy(buffer, "Generation the public/private keypair failed (Dilithium)");
            printf("ERROR: %s\n", buffer);
            send(sock, buffer, strlen(buffer), 0);
            return flag;
        }

        ret = crypto_sign(sm, &smlen, m, MLEN, sk); //Sign
        send(sock, &ret, sizeof(ret), 0);
        if(ret)
        {
            flag = 1;
            strcpy(buffer, "Sign failed (Dilithium)");
            printf("ERROR: %s\n", buffer);
            send(sock, buffer, strlen(buffer), 0);
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
            sprintf(buffer, "Verification failed <%d>", ret);
            flag = 1;
        }
        else if(mlen != MLEN) {
            strcpy(buffer, "Message lengths don't match");
            flag = 1;
        }
        else
        {
            for(j = 0; j < mlen; ++j) {
                if(m[j] != m2[j]) {
                    strcpy(buffer, "Messages don't match");
                    flag = 1;
                }
            }
        }

        send(sock, &flag, sizeof(flag), 0);

        if(flag)
        {
            printf("ERROR: %s\n", buffer);
            send(sock, buffer, strlen(buffer), 0);
        }
    }

    return flag;
}

/****** -> Kyber ******/
// opt = 1: Server; opt = 0: Client
int kyber1(int sock, int opt, unsigned char *ss, unsigned char *nsk)
{
    int ret;
    int flag = 0;
    unsigned char buffer[NBYTES];
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES];

    bzero(buffer, NBYTES);
    bzero(pk, CRYPTO_PUBLICKEYBYTES);
    bzero(ct, CRYPTO_CIPHERTEXTBYTES);
    bzero(nsk, CRYPTO_BYTES);

    //KeyGen and Desencapsulate (server)
    if (opt)
    {
        bzero(buffer, NBYTES);
        ret = crypto_kem_keypair(pk, sk); //KeyGen
        
        memcpy(nsk, sk, CRYPTO_BYTES);

        send(sock, &ret, sizeof(ret), 0);
        if(ret)
        {
            flag = 1;
            strcpy(buffer, "Generation the public/private keypair failed (Kyber)");
            printf("ERROR: %s\n", buffer);
            send(sock, buffer, strlen(buffer), 0);
            return flag;
        }

        send(sock, pk, CRYPTO_PUBLICKEYBYTES, 0);
            
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
        memcpy(ct, buffer, CRYPTO_CIPHERTEXTBYTES);

        ret = crypto_kem_dec(ss, ct, sk); //Desencapsulate
        send(sock, &ret, sizeof(ret), 0);
        if (ret)
        {
            flag = 1;
            strcpy(buffer, "Encapsultaion failed");
            send(sock, buffer, strlen(buffer), 0);
            printf("ERROR: %d\n", ret);
            return flag;
        }
    }
    else // Encapsulate
    {
        bzero(pk, CRYPTO_PUBLICKEYBYTES);
        // Keypair
        ret = read(sock, &flag, sizeof(flag));
        if (flag)
        {
            ret = read(sock, buffer, NBYTES);
            buffer[ret] = '\0';
            printf("ERROR: %s\n", buffer);
            return flag;
        }

        //ret = read(sock, pk, CRYPTO_PUBLICKEYBYTES_NH);
        recv_timeout(sock, pk, TW);

        ret = crypto_kem_enc(ct, ss, pk); // Encapsulate
        
        send(sock, &ret, sizeof(ret), 0);
        if(ret)
        {
            flag = 1;
            strcpy(buffer, "Desencapsultaion failed");
            send(sock, buffer, strlen(buffer), 0);
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
void symmetric_enc_dec(int sock, int flag, unsigned char *k1, unsigned char *k2, unsigned char *msg)
{
    int decryptedtext_len;
    /*
      * Buffer for ciphertext. Ensure the buffer is long enough for the
      * ciphertext which may be longer than the plaintext, depending on the
      * algorithm and mode.
    */
    unsigned char ciphertext[BS];
    /* Buffer for the decrypted text */
    //unsigned char decryptedtext[BS];

    bzero(ciphertext, BS);

    // Server
    if (flag)
    {
        
        //recv_timeout(sock, ciphertext, TW);
        recv(sock, ciphertext, BS, 0);
        // Decrypt the ciphertext
        decryptedtext_len = decrypt(ciphertext, strlen(ciphertext), k1, k2, msg);
        // Add a NULL terminator. We are expecting printable text
        msg[decryptedtext_len] = '\0';
    }
    else // client
    {
        // Encrypt the plaintext (key, iv)
        encrypt(msg, strlen(msg), k1, k2, ciphertext);
        send(sock, ciphertext, strlen(ciphertext), 0);
        
        // 0.1 seg
        usleep(1000000);
    }

    return;
}

/****** AES <- ******/
void safe_channel(int sock, int flag) 
{
    unsigned char sk[CRYPTO_BYTES];
    unsigned char ivsk[CRYPTO_BYTES];

    // vault and ssVault
    unsigned char vault[BS];
    unsigned char ssVault[BS];
    unsigned char message[BS];
    bzero(message, BS);

    bzero(sk, CRYPTO_BYTES);
    bzero(ivsk, CRYPTO_BYTES);
    bzero(vault, BS);
    bzero(ssVault, BS);

    // Client
    if (flag == 0)
    {
        size_t cols, rows;
        int **matrix = readmatrix(&rows, &cols, "matlabcode/results/Vault105-1.txt");

        for(size_t i = 0; i < rows; ++i) //Concatena la matrix en una cadena 
        {
            for(size_t j = 0; j < cols; ++j){
                int length = snprintf( NULL, 0, "%d", matrix[i][j] );
                char* str = malloc( length + 1 );
                snprintf( str, length + 1, "%d", matrix[i][j] );
                strcat(vault, str);
                if(!(i == rows - 1 && j == cols - 1))
                    strcat(vault, ",");
            }
        }

        // freeing memory of matrix
        for(size_t i = 0; i < rows; ++i)
            free(matrix[i]);
        free(matrix);
   
        shake256(ssVault, BS, vault, BS);  // Aplica sha-3 256 al vault

        strcat(message, "hello world!");
        printf("Client: vault => %s\n", vault);
    }

    unsigned long long initCycles = rdtsc();
    if (kyber1(sock, flag, sk, sk)) // KEM
    { return; }
    cyclesKY = rdtsc() - initCycles;

    shake256(ivsk, CRYPTO_BYTES, sk, CRYPTO_BYTES);

    initCycles = rdtsc();
    symmetric_enc_dec(sock, flag, sk, ivsk, vault);
    cyclesAES = rdtsc() - initCycles;

    // Server
    if (flag)
    {
        printf("Server: vault => %s\n", vault);
    }
}

/****** -> TLS ******/
void TLS(int sock, char *opt, int opt2, int flag)
{
    //opt2 = 0 no sign || opt2 = 1 server cert verify || opt2 = 2 both verify
    unsigned long long initCycles;

    if (opt2 == 0)//no sign
    {
        cyclesDil = 0;
        safe_channel(sock, flag);
    }
    else if (opt2 == 1)//verificacion server cert
    {
        initCycles = rdtsc();
        if (dilithium1(sock, flag))
        {
            return;
        }
        cyclesDil = rdtsc() - initCycles;
        safe_channel(sock, flag);
    }
    else if (opt2 == 2) // Both
    {
        initCycles = rdtsc();
        if (dilithium1(sock, flag))
        {
            return;
        }
        if (dilithium1(sock, !flag))
        {
            return;
        }
        cyclesDil = rdtsc() - initCycles;
        safe_channel(sock, flag);
    }

    return;
}
/****** TLS <- ******/\
