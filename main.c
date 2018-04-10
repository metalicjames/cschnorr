#include "src/signature.h"

int main() {
    schnorr_key* key = schnorr_key_new();
    if(key == NULL) {
        return -1;
    }

    schnorr_sig* sig;
    if(schnorr_sign(&sig, key, "hello", 5) == 0) {
        return -1;
    }

    if(schnorr_verify(sig, key->pub, "hello", 5) != 1) {
        return -1;
    }
    


    committed_r_key* rkey = committed_r_key_new();
    if(key == NULL) {
        return -1;
    }

    committed_r_sig* rsig;
    if(committed_r_sign(&rsig, rkey, "hello", 5) == 0) {
        return -1;
    }

    if(committed_r_verify(rsig, rkey->pub, "hello", 5) != 1) {
        return -1;
    }

    committed_r_sig* rsig2;
    if(committed_r_sign(&rsig2, rkey, "hellO", 5) == 0) {
        return -1;
    }

    committed_r_key* recovered;
    if(committed_r_recover(rsig, "hello", 5, rsig2, "hellO", 5, rkey->pub, &recovered) != 1) {
        return -1;
    }
    
    schnorr_key conv;
    conv.a = recovered->a;

    schnorr_pubkey convPub;
    convPub.A = rkey->pub->A;

    schnorr_sig* forgery;
    if(schnorr_sign(&forgery, &conv, "random", 6) == 0) {
        return -1;
    }

    if(schnorr_verify(forgery, &convPub, "random", 6) != 1) {
        return -1;
    }

    committed_r_key_free(rkey);
    committed_r_key_free(recovered);
    committed_r_sig_free(rsig);
    committed_r_sig_free(rsig2);
    schnorr_sig_free(sig);
    schnorr_key_free(key);
    schnorr_sig_free(forgery);

    return 0;
}