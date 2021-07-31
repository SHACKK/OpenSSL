#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM *a)
{
    /* Use BN_bn2hex(a) for hex string * Use BN_bn2dec(a) for decimal string */
    char *number_str = BN_bn2dec(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

BIGNUM *euclid2(BIGNUM *a, BIGNUM *b)
{
    BIGNUM *t;

    while(!BN_is_zero(b)) {
        if(BN_cmp(a, b) < 0) {
            t = a;
            a = b;
            b = t;
        }
        if(!BN_sub(a, a, b)) {
            goto err;
        }
    }
    return a;
    err:
    return NULL;
}

int main(int argc, char *argv[])
{
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM  *res;
    //BIGNUM *res = BN_new();

    if(argc!=3) {
        printf("usage : mygcd num1 num2");
        return -1;
    }
    BN_dec2bn(&a, argv[1]);
    BN_dec2bn(&b, argv[2]);
    //BN_dec2bn(&a, "111231231231231231");
    //BN_dec2bn(&b, "2123131231221");
    printBN("a = ", a);
    printBN("b = ", b);
    res = euclid2(a, b);
    printBN("(a,b) = ", res);
    
    if(a != NULL) BN_free(a);
    if(b != NULL) BN_free(a);
    if(res != NULL) BN_free(a);

    return 0;
}
