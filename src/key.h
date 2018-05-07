#ifndef KEY_H_INCLUDED
#define KEY_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#include "context.h"

#include <openssl/ec.h>

typedef struct {
    EC_POINT* A;
} schnorr_pubkey;

typedef struct {
    schnorr_pubkey* pub;
    BIGNUM* a;
} schnorr_key;

schnorr_key* schnorr_key_new(const schnorr_context* ctx);
void schnorr_key_free(schnorr_key* key);

typedef struct {
    EC_POINT* A;
    EC_POINT* R;
} committed_r_pubkey;

typedef struct {
    BIGNUM* a;
    BIGNUM* k;
    committed_r_pubkey* pub;
} committed_r_key;

committed_r_key* committed_r_key_new(const schnorr_context* ctx);
void committed_r_key_free(committed_r_key* key);

#ifdef __cplusplus
}
#endif

#endif
