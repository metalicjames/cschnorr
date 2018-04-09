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
    
    schnorr_sig_free(sig);
    schnorr_key_free(key);

    return 0;
}