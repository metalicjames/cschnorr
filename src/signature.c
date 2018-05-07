#include "signature.h"

#include <string.h>

#include <openssl/obj_mac.h>
#include <openssl/sha.h>

int hash(unsigned char* out, const unsigned char* in, const size_t len) {
    SHA256_CTX sha256CTX;

    if(!SHA256_Init(&sha256CTX)) {
        return 0;
    }

    if(!SHA256_Update(&sha256CTX, in, len)) {
        return 0;
    }

    if(!SHA256_Final(out, &sha256CTX)) {
        return 0;
    }

    return SHA256_DIGEST_LENGTH;
}

int schnorr_sign(const schnorr_context* ctx,
                 schnorr_sig** dest, 
                 const schnorr_key* key, 
                 const unsigned char* msg, 
                 const size_t len) {
    BIGNUM* k = NULL;
    EC_POINT* R = NULL;
    BIGNUM* BNh = NULL;
    BIGNUM* s = NULL;
    int error = 1;

    *dest = malloc(sizeof(schnorr_sig));
    if(*dest == NULL) {
        goto cleanup;
    }
    (*dest)->s = NULL;

    k = BN_new();
    if(k == NULL) {
        goto cleanup;
    }

    if(BN_rand(k, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) != 1) {
        goto cleanup;
    }

    (*dest)->R = EC_POINT_new(ctx->group);
    if((*dest)->R == NULL) {
        goto cleanup;
    }

    if(EC_POINT_mul(ctx->group, (*dest)->R, NULL, ctx->G, k, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    BNh = BN_new();
    if(BNh == NULL) {
        goto cleanup;
    }

    if(gen_h(ctx, msg, len, (*dest)->R, BNh) == 0) {
        goto cleanup;
    }

    s = BN_new();
    if(s == NULL) {
        goto cleanup;
    }

    if(BN_mod_mul(s, BNh, key->a, ctx->order, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    if(BN_mod_sub(s, k, s, ctx->order, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    (*dest)->s = s;

    error = 0;

    cleanup:
    BN_free(BNh);
    BN_free(k);
    if(error) {
        if(*dest != NULL) {
            BN_free((*dest)->s);
        }

        free(*dest);

        return 0;
    }

    return 1;
}

void schnorr_sig_free(schnorr_sig* sig) {
    if(sig != NULL) {
        BN_free(sig->s);
        free(sig);
    }
}

int schnorr_verify(const schnorr_context* ctx,
                   const schnorr_sig* sig,
                   const schnorr_pubkey* pubkey,
                   const unsigned char* msg,
                   const size_t len) {
    BIGNUM* BNh = NULL;
    EC_POINT* R = NULL;
    int retval = 0;

    if(BN_cmp(sig->s, ctx->order) != -1) {
        retval = -1;
        goto cleanup;
    }

    BNh = BN_new();
    if(BNh == NULL) {
        goto cleanup;
    }

    const int genRes = gen_h(ctx, msg, len, sig->R, BNh);
    if(genRes != 1) {
        retval = genRes;
        goto cleanup;
    }

    R = EC_POINT_new(ctx->group);
    if(R == NULL) {
        goto cleanup;
    }

    if(EC_POINT_mul(ctx->group, R, sig->s, pubkey->A, BNh, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    if(EC_POINT_is_at_infinity(ctx->group, R) == 1) {
        retval = -1;
        goto cleanup;
    }
    const int ret = EC_POINT_cmp(ctx->group, R, sig->R, ctx->bn_ctx);

    retval = 1;

    cleanup:
    EC_POINT_free(R);
    BN_free(BNh);

    if(retval != 1) {
        return retval;
    }

    if(ret == 0) {
        return 1;
    } else {
        return -1;
    }
}

int gen_h(const schnorr_context* ctx,
          const unsigned char* msg, 
          const size_t len, 
          const EC_POINT* R, 
          BIGNUM* out) {  
    unsigned char msgHash[32];
    if(hash((unsigned char*)&msgHash, msg, len) == 0) {
        return 0;
    }

    unsigned char payload[65];
    if(EC_POINT_point2oct(ctx->group, R, POINT_CONVERSION_COMPRESSED, payload, 33, ctx->bn_ctx) < 33) {
        return 0;
    }
    memcpy(((unsigned char*)&payload) + 33, msgHash, 32);

    unsigned char h[32];
    if(hash((unsigned char*)&h, payload, 65) == 0) {
        return 0;
    }
   
    if(BN_bin2bn((unsigned char*)&h, 32, out) == NULL) {
        return 0;
    }

    if(BN_is_zero(out) == 1) {
        return -1;
    }
    
    if(BN_cmp(out, ctx->order) != -1) {
        return -1;
    }

    return 1;
}

int committed_r_sign(const schnorr_context* ctx,
                     committed_r_sig** dest,
                     const committed_r_key* key,
                     const unsigned char* msg,
                     const size_t len) {
    BIGNUM* BNh = NULL;
    int error = 1;
    
    *dest = malloc(sizeof(committed_r_sig));
    if(*dest == NULL) {
        goto cleanup;
    }
    (*dest)->s = NULL;

    BNh = BN_new();
    if(BNh == NULL) {
        goto cleanup;
    }

    if(gen_h(ctx, msg, len, key->pub->R, BNh) == 0) {
        goto cleanup;
    }

    (*dest)->s = BN_new();
    if((*dest)->s == NULL) {
        goto cleanup;
    }

    if(BN_mod_mul((*dest)->s, BNh, key->a, ctx->order, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    if(BN_mod_sub((*dest)->s, key->k, (*dest)->s, ctx->order, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    error = 0;

    cleanup:
    BN_free(BNh);
    if(error) {
        if(*dest != NULL) {
            BN_free((*dest)->s);
        }
        free(*dest);
        return 0;
    }

    return 1;
}

int committed_r_verify(const schnorr_context* ctx,
                       const committed_r_sig* sig,
                       const committed_r_pubkey* pubkey,
                       const unsigned char* msg,
                       const size_t len) {
    schnorr_sig* sSig = NULL;
    schnorr_pubkey* pKey = NULL;
    int retval = 0;

    sSig = malloc(sizeof(schnorr_sig));
    if(sSig == NULL) {
        goto cleanup;
    }

    sSig->R = EC_POINT_new(ctx->group);

    EC_POINT_copy(sSig->R, pubkey->R);

    sSig->s = sig->s;

    pKey = malloc(sizeof(schnorr_pubkey));
    if(pKey == NULL) {
        goto cleanup;
    }
    
    pKey->A = pubkey->A;

    retval = schnorr_verify(ctx, sSig, pKey, msg, len);

    cleanup:
    free(sSig);
    free(pKey);

    return retval;
}

void committed_r_sig_free(committed_r_sig* sig) {
    if(sig != NULL) {
        BN_free(sig->s);
        free(sig);
    }
}

int committed_r_recover(const schnorr_context* ctx,
                        const committed_r_sig* sig1,
                        const unsigned char* msg1,
                        const size_t len1,
                        const committed_r_sig* sig2,
                        const unsigned char* msg2,
                        const size_t len2,
                        const committed_r_pubkey* pubkey,
                        committed_r_key** dest) {
    BIGNUM* h1 = NULL;
    BIGNUM* h2 = NULL;
    int retval = 0;

    *dest = malloc(sizeof(committed_r_key));
    if(*dest == NULL) {
        goto cleanup;
    }
    (*dest)->a = NULL;
    (*dest)->k = NULL;
    (*dest)->pub = NULL;

    (*dest)->a = BN_new();
    if((*dest)->a == NULL) {
        goto cleanup;
    }

    (*dest)->k = BN_new();
    if((*dest)->k == NULL) {
        goto cleanup;
    }

    (*dest)->pub = malloc(sizeof(committed_r_pubkey));
    if((*dest)->pub == NULL) {
        goto cleanup;
    }
    (*dest)->pub->A = NULL;

    (*dest)->pub->A = EC_POINT_new(ctx->group);
    if((*dest)->pub->A == NULL) {
        goto cleanup;
    }

    if(BN_mod_sub((*dest)->a, sig2->s, sig1->s, ctx->order, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    h1 = BN_new();
    if(h1 == NULL) {
        goto cleanup;
    }

    int genRes = gen_h(ctx, msg1, len1, pubkey->R, h1);
    if(genRes != 1) {
        retval = genRes;
        goto cleanup;
    }

    h2 = BN_new();
    if(h2 == NULL) {
        goto cleanup;
    }

    genRes = gen_h(ctx, msg2, len2, pubkey->R, h2);
    if(genRes != 1) {
        retval = genRes;
        goto cleanup;
    }

    if(BN_mod_sub(h1, h1, h2, ctx->order, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    if(BN_mod_inverse(h1, h1, ctx->order, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    if(BN_mod_mul((*dest)->a, h1, (*dest)->a, ctx->order, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    if(BN_mod_mul((*dest)->k, h2, (*dest)->a, ctx->order, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    if(BN_mod_add((*dest)->k, sig2->s, (*dest)->k, ctx->order, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    (*dest)->pub->R = EC_POINT_new(ctx->group);
    if((*dest)->pub->R == NULL) {
        goto cleanup;
    }

    if(EC_POINT_mul(ctx->group, (*dest)->pub->R, NULL, ctx->G, (*dest)->k, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    if(EC_POINT_mul(ctx->group, (*dest)->pub->A, NULL, ctx->G, (*dest)->a, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    retval = 1;

    cleanup:
    BN_free(h1);
    BN_free(h2);
    if(retval != 1) {
        if(*dest != NULL) {
            BN_free((*dest)->a);
            BN_free((*dest)->k);
            if((*dest)->pub != NULL) {
                EC_POINT_free((*dest)->pub->A);
                free((*dest)->pub);
            }
            free(*dest);
        }

        return 0;
    }

    return 1;
}