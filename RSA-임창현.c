#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a)
{
        char * number_str = BN_bn2dec(a);
        printf("%s %s\n", msg, number_str);
        OPENSSL_free(number_str);
}

BIGNUM* KEY_GEN(BIGNUM* p, BIGNUM* q, BIGNUM* e, BIGNUM* n)
{
    BIGNUM* n = BN_new();
    BIGNUM* phi_n = BN_new();
    BIGNUM* d = BN_new();
    BIGNUM* one = BN_new();
    BN_one(one);
    BN_CTX* ctx = BN_CTX_new();

    BN_mul(n, p, q, ctx);
    BN_mul(phi_n, BN_sub(p, p, one), BN_sub(q, q, 1), ctx);


    // BN_mod_inverse(d, e, n, ctx);

    return d;
}

int main() {

    return 0;   
}