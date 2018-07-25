#include "multisig.h"

#include <string.h>

musig_key* musig_key_new(const schnorr_context* ctx) {
    musig_key* ret = NULL;
    schnorr_key* key = NULL;
    int error = 1;

    key = schnorr_key_new(ctx);
    if(key == NULL) {
        goto cleanup;
    }

    ret = malloc(sizeof(musig_key));
    if(ret == NULL) {
        goto cleanup;
    }
    ret->pub = NULL;

    ret->a = key->a;

    ret->pub = malloc(sizeof(musig_pubkey));
    if(ret == NULL) {
        goto cleanup;
    }
    ret->pub->A = NULL;
    ret->pub->R = NULL;

    ret->k = BN_new();
    if(ret->k == NULL) {
        goto cleanup;
    }

    if(BN_rand(ret->k, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) != 1) {
        goto cleanup;
    }

    ret->pub->R = EC_POINT_new(ctx->group);
    if(ret->pub->R == NULL) {
        goto cleanup;
    }

    if(EC_POINT_mul(ctx->group, ret->pub->R, NULL, ctx->G, ret->k, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    ret->pub->A = key->pub->A;

    error = 0;

    cleanup:
    if(error) {
        schnorr_key_free(key);
        EC_POINT_free(ret->pub->R);
        free(ret->pub);
        free(ret);
        return NULL;
    } else {
        free(key->pub);
        free(key);
    }

    return ret;
}

int gen_L(const schnorr_context* ctx,
           musig_pubkey** pubkeys,
           const size_t n,
           unsigned char* L) {
    int error = 1;

    unsigned char* payload = malloc(n * 33 * sizeof(unsigned char));
    if(payload == NULL) {
        return 0;
    }

    int i = 0;
    for(musig_pubkey** key = pubkeys;
        key < pubkeys + n;
        key++) {
        if(EC_POINT_point2oct(ctx->group,
                              (*key)->A,
                              POINT_CONVERSION_COMPRESSED,
                              payload + (i * 33),
                              33,
                              ctx->bn_ctx) == 0) {
            goto cleanup;
        }
        i++;
    }

    if(hash(L, payload, n * 33 * sizeof(unsigned char)) == 0) {
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

int gen_X(const schnorr_context* ctx,
          musig_pubkey** pubkeys,
          const size_t n,
          const unsigned char* L,
          EC_POINT* X) {
    EC_POINT* tmp = NULL;
    int error = 1;
    BIGNUM* BNh = BN_new();
    if(BNh == NULL) {
        goto cleanup;
    }

    tmp = EC_POINT_new(ctx->group);
    if(tmp == NULL) {
        goto cleanup;
    }

    for(musig_pubkey** key = pubkeys;
        key < pubkeys + n;
        key++) {
        unsigned char payload[65];
        if(EC_POINT_point2oct(ctx->group,
                              (*key)->A,
                              POINT_CONVERSION_COMPRESSED,
                              &payload[32],
                              33,
                              ctx->bn_ctx) == 0) {
            goto cleanup;
        }

        memcpy(payload, L, 32);

        unsigned char h[32];
        if(hash(&h[0], payload, 65) == 0) {
            goto cleanup;
        }

        if(BN_bin2bn(&h[0], 32, BNh) == 0) {
            goto cleanup;
        }

        if(EC_POINT_mul(ctx->group, tmp, NULL, (*key)->A, BNh, ctx->bn_ctx) == 0) {
            goto cleanup;
        }

        if(EC_POINT_add(ctx->group, X, tmp, X, ctx->bn_ctx) == 0) {
            goto cleanup;
        }
    }

    error = 0;

    cleanup:
    EC_POINT_free(tmp);
    BN_free(BNh);
    if(error) {
        return 0;
    }

    return 1;
}

int aggregate_R(const schnorr_context* ctx,
                musig_pubkey** pubkeys,
                const size_t n,
                EC_POINT* R) {
    for(musig_pubkey** key = pubkeys;
        key < pubkeys + n;
        key++) {

        if(EC_POINT_add(ctx->group, R, (*key)->R, R, ctx->bn_ctx) == 0) {
            return 0;
        }
    }

    return 1;
}

int point_to_buf(const schnorr_context* ctx,
          unsigned char* r,
          const EC_POINT* R) {
    int error = 0;

    if(EC_POINT_point2oct(ctx->group, R, POINT_CONVERSION_COMPRESSED, r, 33, ctx->bn_ctx) < 33) {
        goto cleanup;
    }

    error = 1;

    cleanup:

    return error;
}

int gen_H1(const schnorr_context* ctx,
           const EC_POINT* pubkey,
           const EC_POINT* R,
           const unsigned char* msg,
           const size_t len,
           unsigned char* dest) {
    unsigned char h1_buf[33 + 33 + 32];

    if(EC_POINT_point2oct(ctx->group,
                          pubkey,
                          POINT_CONVERSION_COMPRESSED,
                          &h1_buf[0],
                          33,
                          ctx->bn_ctx) != 33) {
        return 0;
    }

    if(EC_POINT_point2oct(ctx->group,
                          R,
                          POINT_CONVERSION_COMPRESSED,
                          &h1_buf[33],
                          33,
                          ctx->bn_ctx) != 33) {
        return 0;
    }

    if(hash(&h1_buf[66], msg, len) == 0) {
        return 0;
    }

    if(hash(dest, &h1_buf[0], 33+33+32) == 0) {
        return 0;
    }

    return 1;
}

int musig_sign_single(const schnorr_context* ctx,
                      musig_sig** dest,
                      const musig_key* key,
                      const unsigned char* msg,
                      const size_t len) {
    BIGNUM* tmp = NULL;
    *dest = NULL;
    int error = 0;

    unsigned char h1[32];
    if(gen_H1(ctx, key->pub->A, key->pub->R, msg, len, &h1[0]) != 1) {
        goto cleanup;
    }

    tmp = BN_new();
    if(tmp == NULL) {
        goto cleanup;
    }

    if(BN_bin2bn(&h1[0], 32, tmp) == NULL) {
        goto cleanup;
    }

    if(BN_mod_mul(tmp, tmp, key->a, ctx->order, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    *dest = malloc(sizeof(musig_sig));
    if(*dest == NULL) {
        goto cleanup;
    }
    (*dest)->s = NULL;
    (*dest)->R = NULL;

    (*dest)->s = BN_new();
    if((*dest)->s == NULL) {
        goto cleanup;
    }

    if(BN_mod_add((*dest)->s, tmp, key->k, ctx->order, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    (*dest)->R = EC_POINT_new(ctx->group);
    if((*dest)->R == NULL) {
        goto cleanup;
    }

    if(EC_POINT_copy((*dest)->R, key->pub->R) != 1) {
        goto cleanup;
    }

    error = 1;

    cleanup:
    BN_free(tmp);
    if(error != 1) {
        musig_sig_free(*dest);
    }

    return error;
}

int musig_sign(const schnorr_context* ctx,
               musig_sig** dest,
               musig_pubkey** pub,
               const musig_key* key,
               musig_pubkey** pubkeys,
               const size_t n,
               const unsigned char* msg,
               const size_t len) {
    EC_POINT* X = NULL;
    EC_POINT* R = NULL;
    BIGNUM* tmp = NULL;
    BIGNUM* tmp2 = NULL;
    *dest = NULL;
    *pub = NULL;
    int error = 0;

    unsigned char L[32];
    if(gen_L(ctx, pubkeys, n, &L[0]) == 0) {
        goto cleanup;
    }

    X = EC_POINT_new(ctx->group);
    if(X == NULL) {
        goto cleanup;
    }

    if(gen_X(ctx, pubkeys, n, L, X) == 0) {
        goto cleanup;
    }

    R = EC_POINT_new(ctx->group);
    if(R == NULL) {
        goto cleanup;
    }

    const int ret = aggregate_R(ctx, pubkeys, n, R);
    if(ret != 1) {
        error = ret;
        goto cleanup;
    }

    unsigned char h1[32];
    if(gen_H1(ctx, X, R, msg, len, &h1[0]) != 1) {
        goto cleanup;
    }

    unsigned char h2_buf[32 + 33];
    memcpy(&h2_buf, &L, 32);

    if(EC_POINT_point2oct(ctx->group,
                          key->pub->A,
                          POINT_CONVERSION_COMPRESSED,
                          &h2_buf[32],
                          33,
                          ctx->bn_ctx) != 33) {
        goto cleanup;
    }

    unsigned char h2[32];
    if(hash(&h2[0], &h2_buf[0], 33+32) == 0) {
        goto cleanup;
    }

    tmp = BN_new();
    if(tmp == NULL) {
        goto cleanup;
    }

    if(BN_bin2bn(&h1[0], 32, tmp) == NULL) {
        goto cleanup;
    }

    tmp2 = BN_new();
    if(tmp2 == NULL) {
        goto cleanup;
    }

    if(BN_bin2bn(&h2[0], 32, tmp2) == NULL) {
        goto cleanup;
    }

    if(BN_mod_mul(tmp, tmp2, tmp, ctx->order, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    if(BN_mod_mul(tmp, tmp, key->a, ctx->order, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    *dest = malloc(sizeof(musig_sig));
    if(*dest == NULL) {
        goto cleanup;
    }

    (*dest)->s = BN_new();
    if((*dest)->s == NULL) {
        goto cleanup;
    }

    if(BN_mod_add((*dest)->s, tmp, key->k, ctx->order, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    (*dest)->R = R;

    *pub = malloc(sizeof(musig_pubkey));
    if(*pub == NULL) {
        goto cleanup;
    }
    (*pub)->A = X;
    (*pub)->R = NULL;

    error = 1;

    cleanup:
    BN_free(tmp);
    BN_free(tmp2);
    if(error != 1) {
        EC_POINT_free(R);
        EC_POINT_free(X);
        if(*dest != NULL) {
            BN_free((*dest)->s);
            free(*dest);
        }

        if(*pub != NULL) {
            free(*pub);
        }
    }

    return error;
}

int musig_verify(const schnorr_context* ctx,
                 const musig_sig* sig,
                 const musig_pubkey* pubkey,
                 const unsigned char* msg,
                 const size_t len) {
    EC_POINT* sG = NULL;
    EC_POINT* HX = NULL;
    BIGNUM* tmp = NULL;
    int error = 0;

    sG = EC_POINT_new(ctx->group);
    if(sG == NULL) {
        goto cleanup;
    }

    if(EC_POINT_mul(ctx->group, sG, NULL, ctx->G, sig->s, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    unsigned char h1[32];
    if(gen_H1(ctx, pubkey->A, sig->R, msg, len, &h1[0]) != 1) {
        goto cleanup;
    }

    tmp = BN_new();
    if(tmp == NULL) {
        goto cleanup;
    }

    if(BN_bin2bn(&h1[0], 32, tmp) == NULL) {
        goto cleanup;
    }

    HX = EC_POINT_new(ctx->group);
    if(HX == NULL) {
        goto cleanup;
    }

    if(EC_POINT_mul(ctx->group, HX, NULL, pubkey->A, tmp, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    if(EC_POINT_add(ctx->group, HX, HX, sig->R, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    const int res = EC_POINT_cmp(ctx->group, HX, sG, ctx->bn_ctx);
    switch(res) {
        case 0:
            break;
        case 1:
            error = -1;
            goto cleanup;
        default:
            goto cleanup;
    }

    error = 1;

    cleanup:
    EC_POINT_free(sG);
    EC_POINT_free(HX);
    BN_free(tmp);

    return error;
}

int musig_aggregate(const schnorr_context* ctx,
                    musig_sig** sig,
                    musig_sig** sigs,
                    const size_t n) {
    int error = 0;
    *sig = NULL;
    *sig = malloc(sizeof(musig_sig));
    if(*sig == NULL) {
        goto cleanup;
    }
    (*sig)->s = NULL;
    (*sig)->R = NULL;

    (*sig)->s = BN_new();
    if((*sig)->s == NULL) {
        goto cleanup;
    }

    for(musig_sig** cur = sigs;
        cur < sigs + n;
        cur++) {
        if(BN_mod_add((*sig)->s, (*sig)->s, (*cur)->s, ctx->order, ctx->bn_ctx) == 0) {
            goto cleanup;
        }
    }

    (*sig)->R = EC_POINT_new(ctx->group);
    if((*sig)->R == NULL) {
        goto cleanup;
    }

    if(EC_POINT_copy((*sig)->R, (*sigs)->R) == 0) {
        goto cleanup;
    }

    error = 1;

    cleanup:
    if(error != 1) {
        if(*sig != NULL) {
            EC_POINT_free((*sig)->R);
            BN_free((*sig)->s);
            free(*sig);
        }
    }

    return error;
}

int musig_pubkey_aggregate(const schnorr_context* ctx,
                           musig_pubkey** pubkeys,
                           musig_pubkey** pubkey,
                           const size_t n) {
    EC_POINT* X = NULL;
    *pubkey = NULL;
    int error = 0;

    unsigned char L[32];
    if(gen_L(ctx, pubkeys, n, &L[0]) == 0) {
        goto cleanup;
    }

    X = EC_POINT_new(ctx->group);
    if(X == NULL) {
        goto cleanup;
    }

    if(gen_X(ctx, pubkeys, n, L, X) == 0) {
        goto cleanup;
    }

    *pubkey = malloc(sizeof(musig_pubkey));
    if(*pubkey == NULL) {
        goto cleanup;
    }
    (*pubkey)->A = X;
    (*pubkey)->R = NULL;

    error = 1;

    cleanup:
    if(error != 1) {
        if(*pubkey != NULL) {
            musig_pubkey_free(*pubkey);
        }
        EC_POINT_free(X);
    }

    return error;
}

void musig_key_free(musig_key* key) {
    if(key->k != NULL) {
        BN_free(key->k);
    }
    if(key->a != NULL) {
        BN_free(key->a);
    }

    if(key->pub != NULL) {
        musig_pubkey_free(key->pub);
    }

    free(key);
}

void musig_sig_free(musig_sig* sig) {
    if(sig->s != NULL) {
        BN_free(sig->s);
    }
    if(sig->R != NULL) {
        EC_POINT_free(sig->R);
    }

    free(sig);
}

void musig_pubkey_free(musig_pubkey* key) {
    if(key->A != NULL) {
        EC_POINT_free(key->A);
    }
    if(key->R != NULL) {
        EC_POINT_free(key->R);
    }

    free(key);
}
