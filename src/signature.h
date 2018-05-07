#ifndef SIGNATURE_H_INCLUDED
#define SIGNATURE_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/ec.h>

#include "key.h"

typedef struct {
    EC_POINT* R;
    BIGNUM* s;
} schnorr_sig;


int schnorr_sign(const schnorr_context* ctx,
                 schnorr_sig** dest, 
                 const schnorr_key* key, 
                 const unsigned char* msg, 
                 const size_t len);

int schnorr_verify(const schnorr_context* ctx,
                   const schnorr_sig* sig,
                   const schnorr_pubkey* pubkey,
                   const unsigned char* msg,
                   const size_t len);

void schnorr_sig_free(schnorr_sig* sig);

typedef struct {
    BIGNUM* s;
} committed_r_sig;

int gen_h(const schnorr_context* ctx,
          const unsigned char* msg, 
          const size_t len, 
          const EC_POINT* R, 
          BIGNUM* out);

int committed_r_sign(const schnorr_context* ctx,
                     committed_r_sig** dest,
                     const committed_r_key* key,
                     const unsigned char* msg,
                     const size_t len);

int committed_r_verify(const schnorr_context* ctx,
                       const committed_r_sig* sig,
                       const committed_r_pubkey* pubkey,
                       const unsigned char* msg,
                       const size_t len);

void committed_r_sig_free(committed_r_sig* sig);

int committed_r_recover(const schnorr_context* ctx,
                        const committed_r_sig* sig1,
                        const unsigned char* msg1,
                        const size_t len1,
                        const committed_r_sig* sig2,
                        const unsigned char* msg2,
                        const size_t len2,
                        const committed_r_pubkey* pubkey,
                        committed_r_key** dest);

int hash(unsigned char* out, const unsigned char* in, const size_t len);

#ifdef __cplusplus
}
#endif

#endif
