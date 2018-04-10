#include "key.h"
#include "signature.h"

#include <openssl/obj_mac.h>

schnorr_key* schnorr_key_new() {
    schnorr_key* dest = NULL;
    schnorr_pubkey* pub = NULL;
    EC_GROUP* group = NULL;
    BN_CTX* ctx = NULL;
    int error = 1;

    dest = malloc(sizeof(schnorr_key));
    if(dest == NULL) {
        goto cleanup;
    }
    dest->a = NULL;
    
    dest->a = BN_new();
    if(dest->a == NULL) {
        goto cleanup;
    }

    if(BN_rand(dest->a, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) != 1) {
        goto cleanup;
    }

    if(BN_is_zero(dest->a)) {
        goto cleanup;
    }

    pub = malloc(sizeof(schnorr_pubkey));
    if(pub == NULL) {
        goto cleanup;
    }
    pub->A = NULL;

    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if(group == NULL) {
        goto cleanup;
    }

    const EC_POINT* G = EC_GROUP_get0_generator(group);
    if(G == NULL) {
        goto cleanup;
    }

    ctx = BN_CTX_new();
    if(ctx == NULL) {
        goto cleanup;
    }

    pub->A = EC_POINT_new(group);
    if(pub->A == NULL) {
        goto cleanup;
    }

    if(EC_POINT_mul(group, pub->A, NULL, G, dest->a, ctx) == 0) {
        goto cleanup;
    }

    dest->pub = pub;

    error = 0;

    cleanup:
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    if(error) {
        if(pub != NULL) {
            EC_POINT_free(pub->A);
        }
        free(pub);

        if(dest != NULL) {
            BN_free(dest->a);
        }

        free(dest);

        return NULL;
    }

    return dest;
}

void schnorr_key_free(schnorr_key* key) {
    EC_POINT_free(key->pub->A);
    free(key->pub);
    BN_free(key->a);
    free(key);
}

committed_r_key* committed_r_key_new() {
    committed_r_key* ret = NULL;
    schnorr_key* key = NULL;
    BIGNUM* k = NULL;
    int error = 1;

    key = schnorr_key_new();
    if(key == NULL) {
        goto cleanup;
    }

    ret = malloc(sizeof(committed_r_key));
    if(ret == NULL) {
        goto cleanup;
    }
    ret->pub = NULL;

    ret->a = key->a;

    ret->pub = malloc(sizeof(committed_r_pubkey));
    if(ret == NULL) {
        goto cleanup;
    }

    k = BN_new();
    if(k == NULL) {
        goto cleanup;
    }

    if(gen_r(ret->pub->r, k) == 0) {
        goto cleanup;
    }

    ret->k = k;
    ret->pub->A = key->pub->A;

    error = 0;

    cleanup:
    if(error) {
        BN_free(k);
        schnorr_key_free(key);
        free(ret->pub);
        free(ret);
        return NULL;
    } else {
        free(key->pub);
    }

    return ret;
}

void committed_r_key_free(committed_r_key* key) {
    EC_POINT_free(key->pub->A);
    free(key->pub);
    BN_free(key->a);
    BN_free(key->k);
    free(key);
}