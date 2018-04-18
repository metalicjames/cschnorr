#ifndef MULTISIG_H_INCLUDED
#define MULTISIG_H_INCLUDED

#include "key.h"
#include "signature.h"

int musig_sign(const schnorr_context* ctx,
               schnorr_sig** dest, 
               schnorr_pubkey** pub,
               const committed_r_key* key,
               committed_r_pubkey** pubkeys,
               const size_t n,
               const unsigned char* msg, 
               const size_t len);

int musig_aggregate(const schnorr_context* ctx,
                    schnorr_sig** sig,
                    schnorr_sig** sigs,
                    const size_t n);

int musig_verify(const schnorr_context* ctx,
                 const schnorr_sig* sig,
                 const schnorr_pubkey* pubkey,
                 const unsigned char* msg,
                 const size_t len);

#endif