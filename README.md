# TLSLibrary

Biblioteca TLS para enviar datos de forma segura utilizadon algoritmos de critografía postcuantica.

## Instrucciones para compilar y ejecutar la biblioteca TLS.
Actualmente la compilación y ejecución solo puede realizarse en sistemas operativos linux, preferentemente Ubuntu o cualquier distro basada en este.

Primero debes verificar si tienes instalado Openssh en tu sistema operativo, con el comando:

```shell
 openssl version
```

Esto debe arrojar algo como:

```shell
 OpenSSL 1.1.1f  31 Mar 2020
```

También es recomendable instalar el siguiente paquete:

```shell
 sudo apt-get install libssl-dev
```

Después debes agregar 3 banderas al sistema, para ello ejecutamos los comandos:

```shell
 export CFLAGS="-I/usr/local/opt/openssl@1.1/include"
 export NISTFLAGS="-I/usr/local/opt/openssl@1.1/include"
 export LDFLAGS="-L/usr/local/opt/openssl@1.1/lib"
```

Luego, debemos crear los archivos .so de Kyber. Para ello, nos movemos a la carpeta `kyber/` y ejecutamos el comando:

```shell
  make shared
```
El comando `make shared`, genera nueve archivos con extensión .so. Nosotros sólo utilizaremos dos archivos: 

"libpqcrystals_kyber1024_ref.so", el cual es la implementación de la variante de Kyber que utiliza AES 256 y "libpqcrystals_fips202_ref.so", para utilizar las funciones hash.

Ahora volvemos a la ruta principal de la bibliote TLS, y ejecutamos el comando:

```shell
  make
```
Esto compilará los códigos fuentes y generará el archivo ejecutable del cliente y del servidor. Ahora solo ejecutamos el servidor y los clientes con los comandos:

```shell
  ./server
  ./client 0 kyber
```
Nota: el cliente recibe 2 parameros: el primero determina si queremos utilizar dilithium (0 no usar, 1 usar solo en el servidor, 2 usar en ambos) y el segundo el tipo de algoritmo que usara (kyber o newhope)


