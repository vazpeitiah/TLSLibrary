CC = /usr/bin/gcc
LDFLAGS = -lcrypto -lssl
NISTFLAGS += -march=native -mtune=native -O3 -fomit-frame-pointer
NISTFLAGS += -DMODE=1 -DUSE_AES
NISTFLAGS += -Wno-unused-result -O3
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -O3 -fomit-frame-pointer


SOURCES = pq.c dilithium1aes/sign.c dilithium1aes/polyvec.c dilithium1aes/poly.c \
	dilithium1aes/packing.c dilithium1aes/ntt.c dilithium1aes/reduce.c dilithium1aes/rounding.c \
	dilithium1aes/fips202.c dilithium1aes/aes256ctr.c opensslaes.c \
	kyber/kem.c kyber/indcpa.c kyber/polyvec.c kyber/polyky.c kyber/reduceky.c kyber/nttky.c \
	kyber/cbd.c kyber/verify.c kyber/fips202ky.c kyber/symmetric-shake.c

HEADERS = pq.h dilithium1aes/config.h dilithium1aes/api.h dilithium1aes/params.h dilithium1aes/sign.h \
	dilithium1aes/polyvec.h dilithium1aes/poly.h dilithium1aes/packing.h dilithium1aes/ntt.h \
	dilithium1aes/reduce.h dilithium1aes/rounding.h dilithium1aes/symmetric.h dilithium1aes/fips202.h \
	dilithium1aes/aes256ctr.h opensslaes.h params.h \
	kyber/paramsky.h kyber/apiky.h kyber/indcpa.h kyber/polyvec.h kyber/polyky.h kyber/reduceky.h \
	kyber/nttky.h kyber/cbd.h kyber/verify.h kyber/symmetric.h kyber/fips202ky.h

all: client server
client: client_tls_pq.c dilithium1aes/rng.c $(SOURCES) dilithium1aes/rng.h $(HEADERS) kyber/randombytesky.c
	$(CC) $(NISTFLAGS) $(CFLAGS) -DKYBER_K=2 $< dilithium1aes/rng.c $(SOURCES) kyber/randombytesky.c -o $@ $(LDFLAGS)

server: server_tls_pq.c dilithium1aes/rng.c $(SOURCES) dilithium1aes/rng.h $(HEADERS) kyber/randombytesky.c
	$(CC) $(NISTFLAGS) $(CFLAGS) -DKYBER_K=2 $< dilithium1aes/rng.c $(SOURCES) kyber/randombytesky.c -o $@  $(LDFLAGS)

.PHONY: clean

clean:
	-rm client server
