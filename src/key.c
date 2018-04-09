#include "key.h"

#include <openssl/obj_mac.h>

schnorr_key* schnorr_key_new() {
    schnorr_key* dest = malloc(sizeof(schnorr_key));
    if(dest == NULL) {
        return NULL;
    }
    
    dest->a = BN_new();
    if(dest->a == NULL) {
        return NULL;
    }

    if(BN_rand(dest->a, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) != 1) {
        return NULL;
    }

    if(BN_is_zero(dest->a)) {
        return NULL;
    }

    schnorr_pubkey* pub = malloc(sizeof(schnorr_pubkey));
    if(pub == NULL) {
        return NULL;
    }

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if(group == NULL) {
        return NULL;
    }

    const EC_POINT* G = EC_GROUP_get0_generator(group);
    if(G == NULL) {
        return NULL;
    }

    BN_CTX* ctx = BN_CTX_new();
    if(ctx == NULL) {
        return NULL;
    }

    pub->A = EC_POINT_new(group);
    if(pub->A == NULL) {
        return NULL;
    }

    if(EC_POINT_mul(group, pub->A, NULL, G, dest->a, ctx) == 0) {
        return NULL;
    }

    dest->pub = pub;

    BN_CTX_free(ctx);
    EC_GROUP_free(group);

    return dest;
}

void schnorr_key_free(schnorr_key* key) {
    EC_POINT_free(key->pub->A);
    free(key->pub);
    BN_free(key->a);
    free(key);
}