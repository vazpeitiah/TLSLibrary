CC = /usr/bin/gcc
LDFLAGS = -lcrypto -lssl
NISTFLAGS += -march=native -mtune=native -O3 -fomit-frame-pointer
NISTFLAGS += -DMODE=1 -DUSE_AES

SOURCES_DI = dilithium1aes/polyvec.c dilithium1aes/poly.c dilithium1aes/packing.c \
	dilithium1aes/ntt.c dilithium1aes/reduce.c dilithium1aes/rounding.c \
	dilithium1aes/fips202.c dilithium1aes/aes256ctr.c dilithium1aes/rng.c dilithium1aes/sign.c 

HEADERS_DI = dilithium1aes/config.h dilithium1aes/api.h dilithium1aes/params.h \
	dilithium1aes/sign.h dilithium1aes/polyvec.h dilithium1aes/poly.h \
	dilithium1aes/packing.h dilithium1aes/ntt.h dilithium1aes/reduce.h \
	dilithium1aes/rounding.h dilithium1aes/symmetric.h dilithium1aes/fips202.h  \
	dilithium1aes/aes256ctr.h dilithium1aes/rng.h

KYBER = kyber/ref/libpqcrystals_fips202_ref.so \
		kyber/ref/libpqcrystals_kyber1024_ref.so

SOURCES_KY = kyber/ref/fips202.c kyber/ref/randombytesky.c

HEADERS_KY = kyber/ref/api.h kyber/ref/randombytesky.h kyber/ref/fips202.h

SOURCES = opensslaes.c pq.c vault.c $(SOURCES_DI) $(SOURCES_KY)
HEADERS = opensslaes.h params.h pq.h vault.h $(HEADERS_DI) $(HEADERS_KY)

all: client server

client: client_tls_pq.c  $(SOURCES) $(HEADERS)
	$(CC) -Wall $(NISTFLAGS) $< $(SOURCES) -o $@ $(LDFLAGS) $(KYBER)

server: server_tls_pq.c $(SOURCES)  $(HEADERS)
	$(CC) -Wall $(NISTFLAGS) $< $(SOURCES) -o $@ $(LDFLAGS) $(KYBER)

clean:
	-rm client server Classic-*