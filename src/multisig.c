#include "multisig.h"

#include <string.h>

int gen_L(const schnorr_context* ctx,
           committed_r_pubkey** pubkeys,
           const size_t n,
           unsigned char* L) {
    int error = 1;

    unsigned char* payload = malloc(n * 33 * sizeof(unsigned char));
    if(payload == NULL) {
        return 0;
    }

    int i = 0;
    for(committed_r_pubkey** key = pubkeys; 
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

    if(hash((unsigned char*)&L, payload, n * 33 * sizeof(unsigned char)) == 0) {
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
          committed_r_pubkey** pubkeys,
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

    for(committed_r_pubkey** key = pubkeys; 
        key < pubkeys + n; 
        key++) {
        unsigned char payload[65];
        if(EC_POINT_point2oct(ctx->group, 
                              (*key)->A, 
                              POINT_CONVERSION_COMPRESSED,
                              (unsigned char*)&payload + 32,
                              33,
                              ctx->bn_ctx) == 0) {
            goto cleanup;
        }

        memcpy(payload, L, 32);

        unsigned char h[32];
        if(hash((unsigned char*)&h, payload, 65) == 0) {
            goto cleanup;
        }

        if(BN_bin2bn((unsigned char*)&h, 32, BNh) == 0) {
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

int recover_R(const schnorr_context* ctx,
              const committed_r_pubkey* pubkey,
              EC_POINT* R) {
    int error = 0;
    BIGNUM* Rx = NULL;
    BIGNUM* Ry = NULL;
    BIGNUM* BNr = BN_new();
    if(BNr == NULL) {
        goto cleanup;
    }
    
    if(BN_bin2bn(pubkey->r, 32, BNr) == NULL) {
        goto cleanup;
    }

    if(EC_POINT_set_compressed_coordinates_GFp(ctx->group, R, BNr, 0, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    const int onCurve = EC_POINT_is_on_curve(ctx->group, R, ctx->bn_ctx);
    switch(onCurve) {
        case 1:
            break;
        case 0:
            error = -1;
        default:
            goto cleanup;
    }
    
    if(EC_POINT_is_at_infinity(ctx->group, R) == 1) {
        error = -1;
        goto cleanup;
    }

    Rx = BN_new();
    if(Rx == NULL) {
        goto cleanup;
    }
    
    Ry = BN_new();
    if(Ry == NULL) {
        goto cleanup;
    }

    if(EC_POINT_get_affine_coordinates_GFp(ctx->group, R, Rx, Ry, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    if(BN_is_odd(Ry)) {
        if(EC_POINT_invert(ctx->group, R, ctx->bn_ctx) == 0) {
            goto cleanup;
        }
    }

    error = 1;

    cleanup:
    BN_free(BNr);
    BN_free(Rx);
    BN_free(Ry);

    return error;
 }

int aggregate_R(const schnorr_context* ctx,
          committed_r_pubkey** pubkeys,
          const size_t n,
          EC_POINT* R) {
    int error = 0;
    EC_POINT* cR = EC_POINT_new(ctx->group);
    if(cR == NULL) {
        return 0;
    }

    for(committed_r_pubkey** key = pubkeys; 
        key < pubkeys + n; 
        key++) {

        const int ret = recover_R(ctx, *key, cR);
        if(ret != 1) {
            error = ret;
            goto cleanup;
        }
        
        if(EC_POINT_add(ctx->group, R, cR, R, ctx->bn_ctx) == 0) {
            goto cleanup;
        }
    }

    error = 1;

    cleanup:
    EC_POINT_free(cR);

    return error;
}

int point_to_buf(const schnorr_context* ctx,
          unsigned char* r,
          const EC_POINT* R) {
    BIGNUM* Rx = NULL;
    BIGNUM* Ry = NULL;
    EC_POINT* Rcopy = NULL;
    int error = 0;

    Rcopy = EC_POINT_new(ctx->group);
    if(Rcopy == NULL) {
        goto cleanup;
    }

    if(EC_POINT_copy(Rcopy, R) == 0) {
        goto cleanup;
    }

    Rx = BN_new();
    if(Rx == NULL) {
        goto cleanup;
    }
    
    Ry = BN_new();
    if(Ry == NULL) {
        goto cleanup;
    }

    if(EC_POINT_get_affine_coordinates_GFp(ctx->group, Rcopy, Rx, Ry, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    if(BN_is_odd(Ry)) {
        if(EC_POINT_invert(ctx->group, Rcopy, ctx->bn_ctx) == 0) {
            goto cleanup;
        }

        if(EC_POINT_get_affine_coordinates_GFp(ctx->group, Rcopy, Rx, Ry, ctx->bn_ctx) == 0) {
            goto cleanup;
        }
    }

    if(BN_bn2bin(Rx, r) <= 0) {
        goto cleanup;
    }

    error = 1;

    cleanup:
    BN_free(Rx);
    BN_free(Ry);
    EC_POINT_free(Rcopy);

    return error;
}

int musig_sign(const schnorr_context* ctx,
               schnorr_sig** dest, 
               schnorr_pubkey** pub,
               const committed_r_key* key,
               committed_r_pubkey** pubkeys,
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
    if(gen_L(ctx, pubkeys, n, (unsigned char*)&L) == 0) {
        goto cleanup;
    }

    X = EC_POINT_new(ctx->group);
    if(X == NULL) {
        goto cleanup;
    }

    if(gen_X(ctx, pubkeys, n, L, X) == 0) {
        goto cleanup;
    }
    
    unsigned char h1_buf[33 + 33 + 32];
    if(hash((unsigned char*)&h1_buf + 66, msg, len) == 0) {
        goto cleanup;
    }
    
    if(EC_POINT_point2oct(ctx->group,
                          X,
                          POINT_CONVERSION_COMPRESSED,
                          (unsigned char*)&h1_buf,
                          33,
                          ctx->bn_ctx) != 33) {
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

    if(EC_POINT_point2oct(ctx->group, 
                          R, 
                          POINT_CONVERSION_COMPRESSED, 
                          (unsigned char*)&h1_buf + 33, 
                          33,
                          ctx->bn_ctx) != 33) {
        goto cleanup;
    }

    unsigned char h1[32];
    if(hash((unsigned char*)&h1, (unsigned char*)&h1_buf, 33+33+32) == 0) {
        goto cleanup;
    }

    unsigned int h2_buf[32 + 33];
    memcpy(&h2_buf, &L, 32);

    if(EC_POINT_point2oct(ctx->group, 
                          key->pub->A, 
                          POINT_CONVERSION_COMPRESSED, 
                          (unsigned char*)&h1_buf + 32, 
                          33, 
                          ctx->bn_ctx) != 33) {
        goto cleanup;
    }

    unsigned char h2[32];
    if(hash((unsigned char*)&h2, (unsigned char*)&h2_buf, 33+32) == 0) {
        goto cleanup;
    }

    tmp = BN_new();
    if(tmp == NULL) {
        goto cleanup;
    }

    if(BN_bin2bn((unsigned char*)&h1, 32, tmp) == NULL) {
        goto cleanup;
    }

    tmp2 = BN_new();
    if(tmp2 == NULL) {
        goto cleanup;
    }

    if(BN_bin2bn((unsigned char*)&h2, 32, tmp2) == NULL) {
        goto cleanup;
    }

    if(BN_mul(tmp, tmp2, tmp, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    if(BN_mul(tmp, tmp, key->a, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    *dest = malloc(sizeof(schnorr_sig));
    if(*dest == NULL) {
        goto cleanup;
    }

    (*dest)->s = BN_new();
    if((*dest)->s == NULL) {
        goto cleanup;
    }

    if(BN_add((*dest)->s, tmp, key->k) == 0) {
        goto cleanup;
    }

    if(point_to_buf(ctx, (*dest)->r, R) == 0) {
        goto cleanup;
    }

    *pub = malloc(sizeof(schnorr_pubkey));
    if(*pub == NULL) {
        goto cleanup;
    }
    (*pub)->A = X;

    error = 1;

    cleanup:
    BN_free(tmp);
    BN_free(tmp2);
    EC_POINT_free(R);
    if(error != 1) {
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
                 const schnorr_sig* sig,
                 const schnorr_pubkey* pubkey,
                 const unsigned char* msg,
                 const size_t len) {
    EC_POINT* sG = NULL;
    EC_POINT* R = NULL;
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

    R = EC_POINT_new(ctx->group);
    if(R == NULL) {
        goto cleanup;
    }

    committed_r_pubkey tempPub;
    memcpy(tempPub.r, sig->r, 32);

    const int retval = recover_R(ctx, &tempPub, R);
    switch(retval) {
        case 0:
            goto cleanup;
        case 1:
            break;
        default:
            error = -1;
            goto cleanup;
    }

    unsigned char h1_buf[33 + 33 + 32];
    if(hash((unsigned char*)&h1_buf + 66, msg, len) == 0) {
        goto cleanup;
    }
    
    if(EC_POINT_point2oct(ctx->group,
                          pubkey->A,
                          POINT_CONVERSION_COMPRESSED,
                          (unsigned char*)&h1_buf,
                          33,
                          ctx->bn_ctx) != 33) {
        goto cleanup;
    }

    if(EC_POINT_point2oct(ctx->group, 
                          R, 
                          POINT_CONVERSION_COMPRESSED, 
                          (unsigned char*)&h1_buf + 33, 
                          33,
                          ctx->bn_ctx) != 33) {
        goto cleanup;
    }

    unsigned char h1[32];
    if(hash((unsigned char*)&h1, (unsigned char*)&h1_buf, 33+33+32) == 0) {
        goto cleanup;
    }

    tmp = BN_new();
    if(tmp == NULL) {
        goto cleanup;
    }

    if(BN_bin2bn((unsigned char*)&h1, 32, tmp) == NULL) {
        goto cleanup;
    }

    HX = EC_POINT_new(ctx->group);
    if(HX == NULL) {
        goto cleanup;
    }

    if(EC_POINT_mul(ctx->group, HX, NULL, pubkey->A, tmp, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    if(EC_POINT_add(ctx->group, HX, HX, R, ctx->bn_ctx) == 0) {
        goto cleanup;
    }

    const int res = EC_POINT_cmp(ctx->group, HX, sG, ctx->bn_ctx);
    switch(res) {
        case 0:
            error = -1;
            goto cleanup;
        case 1:
            break;
        default:
            goto cleanup;
    }

    error = 1;

    cleanup:
    EC_POINT_free(sG);
    EC_POINT_free(R);
    EC_POINT_free(HX);
    BN_free(tmp);

    return error;
}

int musig_aggregate(const schnorr_context* ctx,
                    schnorr_sig** sig,
                    schnorr_sig** sigs,
                    const size_t n) {
    int error = 0;
    *sig = NULL;
    *sig = malloc(sizeof(schnorr_sig));
    if(*sig == NULL) {
        goto cleanup;
    }
    (*sig)->s = NULL;

    (*sig)->s = BN_new();
    if((*sig)->s == NULL) {
        goto cleanup;
    }
    
    for(schnorr_sig** cur = sigs; 
        cur < sigs + n; 
        cur++) {
        if(BN_add((*sig)->s, (*sig)->s, (*cur)->s) == 0) {
            goto cleanup;
        }
    }

    error = 1;

    cleanup:
    if(error != 1) {
        if(*sig != NULL) {
            BN_free((*sig)->s);
            free(*sig);
        }
    }

    return error;
}