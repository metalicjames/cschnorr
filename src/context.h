#ifndef CONTEXT_H_INCLUDED
#define CONTEXT_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/ec.h>

typedef struct {
    EC_GROUP* group;
    const EC_POINT* G;
    BIGNUM* order;
    BN_CTX* bn_ctx;
} schnorr_context;

schnorr_context* schnorr_context_new();
void schnorr_context_free(schnorr_context* ctx);

#ifdef __cplusplus
}
#endif

#endif
