/* 
    vault.h: este archivo contiene las funciones necesarias para leer el vault resultante
    de la ejecucion del programa implementado en MATLAB, el cual es una matriz alamcenada
    en un archivo de texto 
*/

/* 
    FUNCION READVAULT
    descripcion: funcion para leer la matriz vault desde un archivo de texto
    parametros: rows cols filename 
        rows:   apuntador a una variable de tipo size_t donde se alamcenara el numero
                de filas de la matriz vault 
        cols:   apuntador a una variable de tipo size_t donde se alamcenara el numero
                de columnas de la matriz vault 
        filename: apuntador a char que almacena la ruta absoluta donde se encuentra el 
                archivo de texto donde esta la matriz vault
    retorna un apuntador doble de enteros, el cual es la matriz vualt
*/
int **readVault(size_t *rows, size_t *cols, const char *filename);

/* 
    FUNCION GETVAULTSTR
    descripcion: funcion que devuelve la matriz vault como una cadena de texto
    parametros: vault path
        vault: apuntador a caracter donde se almacenara el valor del vault
        path: apuntador a char que almacena la ruta absoluta donde se encuentra el 
                archivo de texto donde esta la matriz vault
*/
void getVaultStr(char *vault, const char *path);