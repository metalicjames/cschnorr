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

int schnorr_sign(schnorr_sig** dest, 
                 const schnorr_key* key, 
                 const unsigned char* msg, 
                 const size_t len) {
    *dest = malloc(sizeof(schnorr_sig));
    if(*dest == NULL) {
        return 0;
    }

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if(group == NULL) {
        return 0;
    }

    (*dest)->R = EC_POINT_new(group);
    if((*dest)->R == NULL) {
        return 0;
    }

    BIGNUM* k = BN_new();
    if(k == NULL) {
        return 0;
    }

    if(BN_rand(k, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) != 1) {
        return 0;
    }

    BN_CTX* ctx = BN_CTX_new();
    if(ctx == NULL) {
        return 0;
    }

    const EC_POINT* G = EC_GROUP_get0_generator(group);
    if(G == NULL) {
        return 0;
    }

    genR:
    if(EC_POINT_mul(group, (*dest)->R, NULL, G, k, ctx) == 0) {
        return 0;
    }

    BIGNUM* Rx = BN_new();
    if(Rx == NULL) {
        return 0;
    }
    
    BIGNUM* Ry = BN_new();
    if(Ry == NULL) {
        return 0;
    }

    if(EC_POINT_get_affine_coordinates_GFp(group, (*dest)->R, Rx, Ry, ctx) == 0) {
        return 0;
    }

    if(BN_is_odd(Ry)) {
        BIGNUM* tmp = BN_new();
        if(tmp == NULL) {
            return 0;
        }
        BN_zero(tmp);
        if(BN_sub(k, tmp, k) == 0) {
            return 0;
        }
        BN_free(tmp);

        goto genR;
    }

    unsigned char r[32];

    if(BN_bn2bin(Rx, (unsigned char*)&r) <= 0) {
        return 0;
    }

    unsigned char msgHash[32];
    if(hash((unsigned char*)&msgHash, msg, len) == 0) {
        return 0;
    }

    unsigned char payload[64];
    memcpy(&payload, r, 32);
    memcpy(((unsigned char*)&payload) + 32, msgHash, 32);

    unsigned char h[32];
    if(hash((unsigned char*)&h, payload, 64) == 0) {
        return 0;
    }

    BIGNUM* BNh = BN_new();
    if(BNh == NULL) {
        return 0;
    }

    if(BN_bin2bn((unsigned char*)&h, 32, BNh) == NULL) {
        return 0;
    }

    if(BN_is_zero(BNh) == 1) {
        return 0;
    }

    BIGNUM* order = BN_new();
    if(order == NULL) {
        return 0;
    }

    if(EC_GROUP_get_order(group, order, ctx) == 0) {
        return 0;
    }
    
    if(BN_cmp(BNh, order) != -1) {
        return 0;
    }

    BIGNUM* s = BN_new();
    if(s == NULL) {
        return 0;
    }

    if(BN_mul(s, BNh, key->a, ctx) == 0) {
        return 0;
    }

    if(BN_sub(s, k, s) == 0) {
        return 0;
    }

    (*dest)->s = s;

    EC_GROUP_free(group);
    BN_free(order);
    BN_free(BNh);
    BN_free(Rx);
    BN_free(Ry);
    BN_CTX_free(ctx);
    BN_free(k);

    return 1;
}

void schnorr_sig_free(schnorr_sig* sig) {
    EC_POINT_free(sig->R);
    BN_free(sig->s);
    free(sig);
}

int schnorr_verify(const schnorr_sig* sig,
                   const schnorr_pubkey* pubkey,
                   const unsigned char* msg,
                   const size_t len) {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if(group == NULL) {
        return 0;
    }

    if(EC_POINT_is_at_infinity(group, sig->R) == 1) {
        return -1;
    }

    BN_CTX* ctx = BN_CTX_new();
    if(ctx == NULL) {
        return 0;
    }

    BIGNUM* order = BN_new();
    if(order == NULL) {
        return 0;
    }

    if(EC_GROUP_get_order(group, order, ctx) == 0) {
        return 0;
    }

    BIGNUM* Rx = BN_new();
    if(Rx == NULL) {
        return 0;
    }
    
    BIGNUM* Ry = BN_new();
    if(Ry == NULL) {
        return 0;
    }

    if(EC_POINT_get_affine_coordinates_GFp(group, sig->R, Rx, Ry, ctx) == 0) {
        return 0;
    }

    if(BN_is_odd(Ry)) {
        return -1;
    }

    unsigned char r[32];
    if(BN_bn2bin(Rx, (unsigned char*)&r) <= 0) {
        return 0;
    }

    unsigned char msgHash[32];
    if(hash((unsigned char*)&msgHash, msg, len) == 0) {
        return 0;
    }

    unsigned char payload[64];
    memcpy(&payload, r, 32);
    memcpy(((unsigned char*)&payload) + 32, msgHash, 32);

    unsigned char h[32];
    if(hash((unsigned char*)&h, payload, 64) == 0) {
        return 0;
    }

    BIGNUM* BNh = BN_new();
    if(BNh == NULL) {
        return 0;
    }

    if(BN_bin2bn((unsigned char*)&h, 32, BNh) == NULL) {
        return 0;
    }

    if(BN_is_zero(BNh) == 1) {
        return 0;
    }
    
    if(BN_cmp(BNh, order) != -1) {
        return 0;
    }

    EC_POINT* R = EC_POINT_new(group);
    if(R == NULL) {
        return 0;
    }

    if(EC_POINT_mul(group, R, sig->s, pubkey->A, BNh, ctx) == 0) {
        return 0;
    }

    BIGNUM* RRx = BN_new();
    if(RRx == NULL) {
        return 0;
    }
    
    BIGNUM* RRy = BN_new();
    if(RRy == NULL) {
        return 0;
    }

    if(EC_POINT_get_affine_coordinates_GFp(group, R, RRx, RRy, ctx) == 0) {
        return 0;
    }

    if(BN_is_odd(RRy)) {
        return -1;
    }

    if(EC_POINT_is_at_infinity(group, R) == 1) {
        return -1;
    }

    const int ret = EC_POINT_cmp(group, R, sig->R, ctx);
    if(ret == -1) {
        return 0;
    }
    
    if(ret == 1) {
        return -1;
    }

    EC_GROUP_free(group);
    EC_POINT_free(R);
    BN_CTX_free(ctx);
    BN_free(RRx);
    BN_free(RRy);
    BN_free(Rx);
    BN_free(Ry);
    BN_free(BNh);
    BN_free(order);

    return 1;
}