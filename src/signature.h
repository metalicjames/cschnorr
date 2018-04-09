#ifndef SIGNATURE_H_INCLUDED
#define SIGNATURE_H_INCLUDED

#include <openssl/ec.h>

#include "key.h"

typedef struct {
    EC_POINT* R;
    BIGNUM* s;
} schnorr_sig;


int schnorr_sign(schnorr_sig** dest, 
                 const schnorr_key* key, 
                 const unsigned char* msg, 
                 const size_t len);

int schnorr_verify(const schnorr_sig* sig,
                   const schnorr_pubkey* pubkey,
                   const unsigned char* msg,
                   const size_t len);

void schnorr_sig_free(schnorr_sig* sig);

#endif