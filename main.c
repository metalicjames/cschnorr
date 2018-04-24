#include "src/signature.h"
#include "src/multisig.h"

int run() {
    schnorr_context* ctx = schnorr_context_new();
    if(ctx == NULL) {
        return -1;
    }

    /*schnorr_key* key = schnorr_key_new(ctx);
    if(key == NULL) {
        return -1;
    }

    schnorr_sig* sig;
    if(schnorr_sign(ctx, &sig, key, "hello", 5) == 0) {
        return -1;
    }

    if(schnorr_verify(ctx, sig, key->pub, "hello", 5) != 1) {
        return -1;
    }*/
    


    committed_r_key* rkey = committed_r_key_new(ctx);
    if(rkey == NULL) {
        return -1;
    }

    /*committed_r_sig* rsig;
    if(committed_r_sign(ctx, &rsig, rkey, "hello", 5) == 0) {
        return -1;
    }

    if(committed_r_verify(ctx, rsig, rkey->pub, "hello", 5) != 1) {
        return -1;
    }

    committed_r_sig* rsig2;
    if(committed_r_sign(ctx, &rsig2, rkey, "hellO", 5) == 0) {
        return -1;
    }

    committed_r_key* recovered;
    if(committed_r_recover(ctx, rsig, "hello", 5, rsig2, "hellO", 5, rkey->pub, &recovered) != 1) {
        return -1;
    }
    
    schnorr_key conv;
    conv.a = recovered->a;

    schnorr_pubkey convPub;
    convPub.A = rkey->pub->A;

    schnorr_sig* forgery;
    if(schnorr_sign(ctx, &forgery, &conv, "random", 6) == 0) {
        return -1;
    }

    if(schnorr_verify(ctx, forgery, &convPub, "random", 6) != 1) {
        return -1;
    }*/

    /*committed_r_key* rkey2 = committed_r_key_new(ctx);
    if(rkey2 == NULL) {
        return -1;
    }

    committed_r_key* keys[2];
    keys[0] = rkey;
    keys[1] = rkey2;

    committed_r_pubkey* pubkeys[2];
    pubkeys[0] = rkey->pub;
    pubkeys[1] = rkey2->pub;

    schnorr_sig* sig1;
    schnorr_sig* sig2;
    schnorr_pubkey* pub;*/

    musig_key* key = musig_key_new(ctx);
    musig_key* keys[1];
    keys[0] = key;

    musig_pubkey* pubkeys[1];
    pubkeys[0] = key->pub;

    musig_sig* sig;
    musig_pubkey* pub;
    if(musig_sign(ctx, &sig, &pub, keys[0], pubkeys, 1, "hello", 5) == 0) {
        return -1;
    }

    /*if(musig_sign(ctx, &sig2, &pub, keys[1], pubkeys, 2, "hello", 5) == 0) {
        return -1;
    }*/

    /*schnorr_sig* sigs[2];
    sigs[0] = sig1;
    sigs[1] = sig2;*/

    /*schnorr_sig* sigAgg;
    if(musig_aggregate(ctx, &sigAgg, sigs, 2) == 0) {
        return -1;
    }*/

    if(musig_verify(ctx, sig, pub, "hello", 5) != 1) {
        char* sHex = BN_bn2hex(sig->s);
        char* AHex = EC_POINT_point2hex(ctx->group, pub->A, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx);
        char* RHex = EC_POINT_point2hex(ctx->group, sig->R, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx);

        printf("s: %s, X: %s, R: %s\n", sHex, AHex, RHex);
        return -1;
    }

    //committed_r_key_free(recovered);
    //committed_r_sig_free(rsig);
    //committed_r_sig_free(rsig2);
    //schnorr_sig_free(sig);
    //schnorr_key_free(key);
    ///schnorr_sig_free(forgery);
    //schnorr_sig_free(sig2);
    //schnorr_sig_free(sigAgg);
    EC_POINT_free(pub->A);
    free(pub);
    schnorr_context_free(ctx);

    return 0;
}

int main() {
    int fails = 0;
    int tot = 0;
    while(fails < 100) {
        switch(run()) {
            case -1:
                fails++;
            default:
                tot++;
                printf("%d / %d (%f%%)\n", fails, tot, ((float)fails / (float)tot)*100);
        }
    }
    
    return 0;
}