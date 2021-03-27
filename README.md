# TLSLibrary

Biblioteca TLS implementada con los algoritmos, de criptografía post-cuántica, Kyber y Dilithium de pq-crystals.

## Instrucciones para compilar
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

Luego, debemos crear los archivos .so de Kyber. Para ello, nos movemos a la carpeta `kyber/ref/` y ejecutamos el comando:

```shell
make shared
```
El comando `make shared`, genera nueve archivos con extensión .so. Nosotros sólo utilizaremos dos archivos: 

"libpqcrystals_kyber1024_ref.so", el cual es la implementación de la variante de Kyber que utiliza AES 256 y "libpqcrystals_fips202_ref.so", para utilizar las funciones hash.

Ahora volvemos a la ruta principal de la bibliote TLS, y ejecutamos el comando:

```shell
make
```
Esto compilará los códigos fuentes y generará el archivo ejecutable del cliente y del servidor.

## Cómo usar

Para ejecutar el servidor, solo ejecutamos el siguiente comando

```shell
./server
```
En el caso del cliente, debemos pasa 2 parametros al momento de ejecutar el programa. El primer parametro indica si se quiere usar el canal seguro (1 para sí y 0 para no usarlo) y el segundo parametro especifica si queremos ultilizar dilithium (0 para no usarlo, 1 para usarlo solo del lado del cliente, y 2 para usarlo el ambos).

Por ejemplo, si deseo utilizar el canal seguro y dilithium para el cliente y el servidor, uso el comando:
```shell
./client 1 2
```
