#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a)
{
        char * number_str = BN_bn2dec(a);
        printf("%s %s\n", msg, number_str);
        OPENSSL_free(number_str);
}

BIGNUM *ExpMod(BIGNUM *res, BIGNUM *a, BIGNUM *e, BIGNUM *m) {
        BIGNUM *A = BN_new();
        BN_dec2bn(&A, "1");
        BIGNUM *B = BN_new();
        BN_copy(B, a);
        // BIGNUM *q = BN_new();
        // BN_dec2bn(q, "1");
        BIGNUM *two = BN_new();
        BN_dec2bn(&two, "2");
        BIGNUM *r = BN_new();
        BN_CTX *ctx = BN_CTX_new();

        while (!BN_is_zero(e))
        {
                BN_div(e,r,e, two, ctx);
                if (BN_is_one(r)) {
                        BN_mul(A, A, B, ctx);
                        BN_mul(B, B, B, ctx);
                } else {
                        BN_mul(B, B, B, ctx);
                }
                BN_mod(A, A, m, ctx);
                BN_mod(B, B, m, ctx);
        }

        BN_copy(res, A);
        return res;
}
 
int main (int argc, char *argv[])
{
        BIGNUM *a = BN_new();
        BIGNUM *e = BN_new();
        BIGNUM *m = BN_new();
        BIGNUM *res = BN_new();

        if(argc != 4){
                printf("usage: exp base exponent modulus\n");
                return -1;
        }

        BN_dec2bn(&a, argv[1]);
        BN_dec2bn(&e, argv[2]);
        BN_dec2bn(&m, argv[3]);
        printBN("a = ", a);
        printBN("e = ", e);
        printBN("m = ", m);

        res = ExpMod(res,a,e,m);

        printBN("a**e mod m = ", res);

        if(a != NULL) BN_free(a);
        if(e != NULL) BN_free(e);
        if(m != NULL) BN_free(m);
        if(res != NULL) BN_free(res);

        return 0;
}

