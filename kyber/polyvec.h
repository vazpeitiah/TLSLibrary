#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "paramsky.h"
#include "polyky.h"

typedef struct{
  poly vec[KYBER_K];
} polyvec;

#define polyvec_compress KYBER_NAMESPACE(_polyvec_compress)
void polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const polyvec *a);
#define polyvec_decompress KYBER_NAMESPACE(_polyvec_decompress)
void polyvec_decompress(polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES]);

#define polyvec_tobytes KYBER_NAMESPACE(_polyvec_tobytes)
void polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const polyvec *a);
#define polyvec_frombytes KYBER_NAMESPACE(_polyvec_frombytes)
void polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES]);

#define polyvec_ntt KYBER_NAMESPACE(_polyvec_ntt)
void polyvec_ntt(polyvec *r);
#define polyvec_invntt_tomont KYBER_NAMESPACE(_polyvec_invntt_tomont)
void polyvec_invntt_tomont(polyvec *r);

#define polyvec_basemul_acc_montgomery KYBER_NAMESPACE(_polyvec_pointwise_acc_montgomery)
void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b);

#define polyvec_reduce KYBER_NAMESPACE(_polyvec_reduce)
void polyvec_reduce(polyvec *r);

#define polyvec_add KYBER_NAMESPACE(_polyvec_add)
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);

#endif
