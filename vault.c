#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "vault.h"

#define BS 1024 /* Tamano del buffer */

int **readVault(size_t *rows, size_t *cols, const char *filename) {
    int **matrix = NULL, **tmp; /* Vault es una matriz mxn  */
    char line[BS];              /* Linea del archivo de texto */

    if(rows == NULL || cols == NULL || filename == NULL) /* Si no se recibieron las variables retorna NULL */
        return NULL; 

    *rows = 0; /* Incializa el valor de las filas en 0 */
    *cols = 0;  /* Incializa el valor de las columnas en 0 */

    FILE *fp = fopen(filename, "r"); /* Abrir el archivo de texto del vault */

    if(fp == NULL) { /* Si no se puede acceder al archivo retorna NULL */
        fprintf(stderr, "could not open %s: %s\n", filename, strerror(errno));
        return NULL;
    }

    while(fgets(line, sizeof line, fp)) {   /* Leermos linea a linea el archivo de texto */
        if(*cols == 0) {        /* Determinamos el numero de columnas, apartir de la primera fila del archivo de texto */
            char *scan = line; 
            int dummy;
            int offset = 0;
            while(sscanf(scan, "%d%n", &dummy, &offset) == 1) /* Leemos el ultimo valor de la linea hasta el final del archivo*/
            {
                scan += offset; /* pasamos a la siguiente linea */
                (*cols)++;      /* incrementamos en uno el numero de columnas  */
            }
        }

        tmp = realloc(matrix, (*rows + 1) * sizeof *matrix); /* Reservamos espacio en memoria para una fila de la matriz */

        if(tmp == NULL) 
        {
            fclose(fp);
            return matrix;
        }

        matrix = tmp;

        matrix[*rows] = calloc(*cols, sizeof *matrix[*rows]); /* Reservamos espacio en memoria para un elemento de la matriz */

        if(matrix[*rows] == NULL) {
            fclose(fp);
            if(*rows == 0) { 
                fclose(fp);
                free(matrix);
                return NULL;
            }

            return matrix;
        }

        int offset = 0;
        char *scan = line;
        for(size_t j = 0; j < *cols; ++j) {
            if(sscanf(scan, "%d%n", matrix[*rows] + j, &offset) == 1)
                scan += offset;
            else
                matrix[*rows][j] = 0; // could not read, set cell to 0
        }
        (*rows)++; // incrementing rows
    }

    fclose(fp);

    return matrix;
}

void getVaultStr(char *vault, const char *path) {
    bzero(vault, BS);                           /* Vault incializado con 0 */

    size_t cols, rows;                              /* Numero de columnas y filas de la matriz */
    int **matrix = readVault(&rows, &cols, path);   /* Leer matriz vault desde archivo de texto */

    for(size_t i = 0; i < rows; ++i)
    {
        for(size_t j = 0; j < cols; ++j){
            int length = snprintf( NULL, 0, "%d", matrix[i][j] );   /* Obtener longitud de caracteres del valor v[i][j] */
            char* str = malloc( length + 1 );                       /* Reservar memoria para esta longitud */
            snprintf( str, length + 1, "%d", matrix[i][j] );        /* Concatenar valor entero v[i][j] a la cadena str */
            strcat(vault, str);                                     /* Concatenar cadena str al vault */
            if(!(i == rows - 1 && j == cols - 1) && j != 1)                   /* Separar datos con un "coma", exepcto el ultimo */
                strcat(vault, " ");
            else if(i != rows -1)
                strcat(vault, "\n");
        }

    }

    for(size_t i = 0; i < rows; ++i)
        free(matrix[i]);
    free(matrix);
}