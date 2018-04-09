#include "key.h"

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