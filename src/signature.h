#ifndef SIGNATURE_H_INCLUDED
#define SIGNATURE_H_INCLUDED

#include <openssl/ec.h>

#include "key.h"

typedef struct {
    unsigned char r[32];
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

typedef struct {
    BIGNUM* s;
} committed_r_sig;

int gen_r(unsigned char* r, BIGNUM* k);
int gen_h(const unsigned char* msg, 
          const size_t len, 
          const unsigned char* r, 
          BIGNUM* out);

int committed_r_sign(committed_r_sig** dest,
                     const committed_r_key* key,
                     const unsigned char* msg,
                     const size_t len);

int committed_r_verify(const committed_r_sig* sig,
                       const committed_r_pubkey* pubkey,
                       const unsigned char* msg,
                       const size_t len);

void committed_r_sig_free(committed_r_sig* sig);

int committed_r_recover(const committed_r_sig* sig1,
                        const unsigned char* msg1,
                        const size_t len1,
                        const committed_r_sig* sig2,
                        const unsigned char* msg2,
                        const size_t len2,
                        const committed_r_pubkey* pubkey,
                        committed_r_key** dest);

#endif