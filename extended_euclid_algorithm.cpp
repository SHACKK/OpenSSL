#include <stdio.h> 
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM *a)
{
    /* Use BN_bn2hex(a) for hex string * Use BN_bn2dec(a) for decimal string */
    char *number_str = BN_bn2dec(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

//(a,b) 의 최대 공약수
//a*(x) + b(y) = gcd
BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b)
{
        BIGNUM *q = BN_new(); // 몫
        BIGNUM *r = BN_new(); // 나머지
        BN_dec2bn(&r, "1");

        BN_CTX *ctx = BN_CTX_new(); 
        BIGNUM *x1 = BN_new();
        BIGNUM *x2 = BN_new();
        BIGNUM *y1 = BN_new();
        BIGNUM *y2 = BN_new();
        BIGNUM *qx2 = BN_new();
        BIGNUM *qy2 = BN_new();
        BIGNUM *pre_a = BN_new();
        BIGNUM *pre_b = BN_new();

        BN_dec2bn(&x1, "1");
        BN_dec2bn(&x2, "0");
        BN_dec2bn(&y1, "0");
        BN_dec2bn(&y2, "1");

        while (!BN_is_zero(r)) // 나머지가 0일때 까지
        {
                // q(몫), r(나머지) 구하기
                BN_div(q, r, a, b, ctx);
                
                // x = x1 - q*x2
                BN_mul(qx2, q, x2, ctx);
                BN_sub(x, x1, qx2);
                
                // y = y1 - q*y2
                BN_mul(qy2, q, y2, ctx);
                BN_sub(y, y1, qy2);

                //대입하는 과정
        }
        //while문 밖에서 한번 더 대입하는 과정
        //pre_a랑 pre_b도 한번 더 대입해줘야함!

}

int main (int argc, char *argv[])
{
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *x = BN_new();
        BIGNUM *y = BN_new();
        BIGNUM *gcd;

        if(argc != 3){
                printf("usage: xeuclid num1 num2");
                return -1;
        }
        BN_dec2bn(&a, argv[1]);
        BN_dec2bn(&b, argv[2]);
        gcd = XEuclid(x,y,a,b);

        printBN("(a,b) = ", gcd);
        printBN("a = ", a);
        printBN("b = ", b);
        printBN("x = ", x);
        printBN("y = ", y);
        printf("%s*(%s) + %s*(%s) = %s\n",BN_bn2dec(a),BN_bn2dec(x),BN_bn2dec(b),BN_bn2dec(y),BN_bn2dec(gcd));

        if(a != NULL) BN_free(a);
        if(b != NULL) BN_free(b);
        if(x != NULL) BN_free(x);
        if(y != NULL) BN_free(y);
        if(gcd != NULL) BN_free(gcd);

        return 0;
}