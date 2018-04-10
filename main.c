#include "src/signature.h"

int main() {
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
    if(key == NULL) {
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

    committed_r_key_free(rkey);
    committed_r_key_free(recovered);
    committed_r_sig_free(rsig);
    committed_r_sig_free(rsig2);
    schnorr_sig_free(sig);
    schnorr_key_free(key);
    schnorr_sig_free(forgery);
    schnorr_context_free(ctx);

    return 0;
}