#ifndef MULTISIG_H_INCLUDED
#define MULTISIG_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#include "key.h"
#include "signature.h"

typedef struct {
    EC_POINT* R;
    BIGNUM* s;
} musig_sig;

typedef struct {
    EC_POINT* A;
    EC_POINT* R;
} musig_pubkey;

typedef struct {
    BIGNUM* a;
    BIGNUM* k;
    musig_pubkey* pub;
} musig_key;

musig_key* musig_key_new(const schnorr_context* ctx);

int musig_sign(const schnorr_context* ctx,
               musig_sig** dest, 
               musig_pubkey** pub,
               const musig_key* key,
               musig_pubkey** pubkeys,
               const size_t n,
               const unsigned char* msg, 
               const size_t len);

int musig_aggregate(const schnorr_context* ctx,
                    musig_sig** sig,
                    musig_sig** sigs,
                    const size_t n);

int musig_verify(const schnorr_context* ctx,
                 const musig_sig* sig,
                 const musig_pubkey* pubkey,
                 const unsigned char* msg,
                 const size_t len);

#ifdef __cplusplus
}
#endif

#endif
