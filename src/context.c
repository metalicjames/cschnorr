#include "context.h"

#include <openssl/obj_mac.h>

void schnorr_context_free(schnorr_context* ctx) {
    if(ctx != NULL) {
        BN_free(ctx->order);
        EC_GROUP_free(ctx->group);
        BN_CTX_free(ctx->bn_ctx);
        free(ctx);
    }
}

schnorr_context* schnorr_context_new() {
    schnorr_context* ctx = malloc(sizeof(schnorr_context));
    if(ctx == NULL) {
        goto error;
    }
    ctx->bn_ctx = NULL;
    ctx->G = NULL;
    ctx->group = NULL;
    ctx->order = NULL;

    ctx->bn_ctx = BN_CTX_new();
    if(ctx->bn_ctx == NULL) {
        goto error;
    }
    
    ctx->group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if(ctx->group == NULL) {
        goto error;
    }

    ctx->G = EC_GROUP_get0_generator(ctx->group);
    if(ctx->G == NULL) {
        goto error;
    }

    ctx->order = BN_new();
    if(ctx->order == NULL) {
        goto error;
    }

    if(EC_GROUP_get_order(ctx->group, ctx->order, ctx->bn_ctx) == 0) {
        goto error;
    }

    return ctx;

    error:
    schnorr_context_free(ctx);
    return NULL;
}