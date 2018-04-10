#include "multisig.h"

int gen_L(const schnorr_context* ctx,
          const schnorr_pubkey* pubkeys,
          const size_t n,
          BIGNUM* L) {
    int error = 1;

    unsigned char* payload = malloc(n * 33 * sizeof(unsigned char));
    if(payload == NULL) {
        return 0;
    }

    int n = 0;
    for(schnorr_pubkey* key = pubkeys; 
        key < pubkeys + n*sizeof(schnorr_pubkey); 
        key += sizeof(schnorr_pubkey)) {
        if(EC_POINT_point2oct(ctx->group, 
                              key->A, 
                              POINT_CONVERSION_COMPRESSED,
                              payload + (n * 33),
                              33,
                              ctx->bn_ctx) == 0) {
            goto cleanup;
        }
        n++;
    }

    unsigned char lbuf[32];
    if(hash((unsigned char*)&lbuf, payload, n * 33 * sizeof(unsigned char)) == 0) {
        goto cleanup;
    }

    if(BN_bin2bn((unsigned char*)&lbuf, 32, L) == NULL) {
        goto cleanup;
    }

    error = 0;

    cleanup:
    free(payload);

    if(error) {
        return 0;
    }

    return 1;
}