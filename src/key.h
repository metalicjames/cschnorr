#ifndef KEY_H_INCLUDED
#define KEY_H_INCLUDED

#include <openssl/ec.h>

typedef struct {
    EC_POINT* A;
} schnorr_pubkey;

typedef struct {
    schnorr_pubkey* pub;
    BIGNUM* a;
} schnorr_key;

schnorr_key* schnorr_key_new();
void schnorr_key_free(schnorr_key* key);

#endif