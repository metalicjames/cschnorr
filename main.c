#include "src/signature.h"
#include "src/multisig.h"

int run() {
    schnorr_context* ctx = schnorr_context_new();
    if(ctx == NULL) {
        return -1;
    }

    schnorr_key* key = schnorr_key_new(ctx);
    if(key == NULL) {
        return -1;
    }

    schnorr_sig* sig;
    if(schnorr_sign(ctx, &sig, key, "hello", 5) == 0) {
        return -1;
    }

    if(schnorr_verify(ctx, sig, key->pub, "hello", 5) != 1) {
        return -1;
    }

    committed_r_key* rkey = committed_r_key_new(ctx);
    if(rkey == NULL) {
        return -1;
    }

    committed_r_sig* rsig;
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
    }

    musig_key* key1 = musig_key_new(ctx);

    musig_sig* sig_single;
    if(musig_sign_single(ctx, &sig_single, key1, "hello", 5) != 1) {
        return -1;
    }

    if(musig_verify(ctx, sig_single, key1->pub, "hello", 5) != 1) {
        return -1;
    }

    musig_key* key2 = musig_key_new(ctx);
    musig_key* keys[2];
    keys[0] = key1;
    keys[1] = key2;

    musig_pubkey* pubkeys[2];
    pubkeys[0] = key1->pub;
    pubkeys[1] = key2->pub;

    musig_sig* sig1;
    musig_sig* sig2;
    musig_pubkey* pub;
    if(musig_sign(ctx, &sig1, &pub, keys[0], pubkeys, 2, "hello", 5) == 0) {
        return -1;
    }

    if(musig_sign(ctx, &sig2, &pub, keys[1], pubkeys, 2, "hello", 5) == 0) {
        return -1;
    }

    musig_sig* sigs[2];
    sigs[0] = sig1;
    sigs[1] = sig2;

    musig_sig* sigAgg;
    if(musig_aggregate(ctx, &sigAgg, sigs, 2) == 0) {
        return -1;
    }

    if(musig_verify(ctx, sigAgg, pub, "hello", 5) != 1) {
        char* sHex = BN_bn2hex(sig->s);
        char* AHex = EC_POINT_point2hex(ctx->group, pub->A, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx);
        char* RHex = EC_POINT_point2hex(ctx->group, sigAgg->R, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx);

        printf("s: %s, X: %s, R: %s\n", sHex, AHex, RHex);
        return -1;
    }

    committed_r_key_free(recovered);
    committed_r_sig_free(rsig);
    committed_r_sig_free(rsig2);
    schnorr_sig_free(sig);
    schnorr_key_free(key);
    schnorr_sig_free(forgery);
    musig_pubkey_free(pub);
    musig_sig_free(sig1);
    musig_sig_free(sig2);
    musig_sig_free(sigAgg);
    musig_sig_free(sig_single);
    musig_key_free(key1);
    musig_key_free(key2);
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
