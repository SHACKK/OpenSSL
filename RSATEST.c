#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a)
{
        char * number_str = BN_bn2dec(a);
        printf("%s %s\n", msg, number_str);
        OPENSSL_free(number_str);
}

void PrintUsage()
{
    printf("usage: rsa [-k|-e e n plaintext|-d d n ciphertext]\n");
}

//RSA 구조체를 생성하여 포인터를 리턴하는 함수
typedef struct _b10rsa_st {
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
}BOB10_RSA;

BOB10_RSA *BOB10_RSA_new() {
    BOB10_RSA *b10rsa = (BOB10_RSA*)malloc(sizeof(BOB10_RSA));
    b10rsa->e = BN_new();
    b10rsa->d = BN_new();
    b10rsa->n = BN_new();

    return b10rsa;
}

// BOB10_RSA *BOB10_RSA_new()
// {
//     BOB10_RSA b10rsa;
//     b10rsa.e = BN_new();
//     b10rsa.d = BN_new();
//     b10rsa.n = BN_new();

//     return &b10rsa;
// }

BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b)
{
    BIGNUM *q = BN_new(); // 몫
    BIGNUM *r = BN_new(); // 나머지
    BN_dec2bn(&r, "1");
    BN_CTX *ctx = BN_CTX_new(); 

    //인자 값 받아서 넣어주기
    BIGNUM *a_ = BN_new();
    BIGNUM *b_ = BN_new();
    BN_copy(a_, a);
    BN_copy(b_, b);

    //기타 필요한 변수 선언
    BIGNUM *x1 = BN_new();
    BIGNUM *x2 = BN_new();
    BIGNUM *y1 = BN_new();
    BIGNUM *y2 = BN_new();
    BIGNUM *qx2 = BN_new();
    BIGNUM *qy2 = BN_new();

    BN_dec2bn(&x1, "1");
    BN_dec2bn(&x2, "0");
    BN_dec2bn(&y1, "0");
    BN_dec2bn(&y2, "1");

    BIGNUM *gcd_ = BN_new();

    while (!BN_is_zero(r)) // 나머지가 0일때 까지
    {
        // q(몫), r(나머지) 구하기
        BN_div(q, r, a_, b_, ctx);
                
        // x = x1 - q*x2
        BN_mul(qx2, q, x2, ctx);
        BN_sub(x, x1, qx2);

        // y = y1 - q*y2
        BN_mul(qy2, q, y2, ctx);
        BN_sub(y, y1, qy2);

        //대입하는 과정
        BN_copy(a_, b_);
        BN_copy(b_, r);
                
        BN_copy(x1, x2);
        BN_copy(x2, x);

        BN_copy(y1, y2);
        BN_copy(y2, y);
    }
    // return gcd_;
    BN_copy(x, x1);
    BN_copy(y, y1);

    return a_;
}

//RSA 구조체 포인터를 해제하는 함수
int BOB10_RSA_free(BOB10_RSA *b10rsa)
{
    BN_free(b10rsa->d);
    BN_free(b10rsa->e);
    BN_free(b10rsa->n);
};

//RSA 키 생성 함수
// 입력 : nBits (RSA modulus bit size)
// 출력 : b10rsa (구조체에 n, e, d 가  생성돼 있어야 함)
int BOB10_RSA_KeyGen(BOB10_RSA *b10rsa, int nBits)
{
    //p, q값 설정
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_hex2bn(&p, "0xC485F491D12EA7E6FEB95794E9FE0A819168AAC9D545C9E2AE0C561622F265FEB965754C875E049B19F3F945F2574D57FA6A2FC0A0B99A2328F107DD16ADA2A7");
    BN_hex2bn(&q, "0xF9A91C5F20FBBCCC4114FEBABFE9D6806A52AECDF5C9BAC9E72A07B0AE162B4540C62C52DF8A8181ABCC1A9E982DEB84DE500B27E902CD8FDED6B545C067CE4F");

    // (p-1), (q-1) 설정
    BIGNUM *p_1 = BN_new();
    BIGNUM *q_1 = BN_new();
    BIGNUM *one = BN_new();
    BN_one(one);
    BN_sub(p_1, p, one);
    BN_sub(q_1, q, one);

    // phi(n) = (p-1)(q-1)
    BIGNUM *phi_n = BN_new();
    BN_mul(b10rsa->n, p, q, ctx);
    BN_mul(phi_n, p_1, q_1, ctx);

    // e 선택, mod phi(n)에 대한 e의 역원 d 구하기
    BN_dec2bn(&b10rsa->e, "31");
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    BIGNUM* gcd;
    gcd = XEuclid(x, y, b10rsa->e, phi_n);
    BN_mod(b10rsa, phi_n, e,);

    return 0;
};

// RSA 암호화 함수
// 입력 : 공개키를 포함한 b10rsa, 메시지 m
// 출력 : 암호문 c
int BOB10_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB10_RSA *b10rsa)
{
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_exp(c, m, b10rsa->e, b10rsa->n, ctx);
    BN_CTX_free(ctx);
};

// RSA 복호화 함수
// 입력 : 공개키를 포함한 b10rsa, 암호문 c
// 출력 : 평문 m
int BOB10_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB10_RSA *b10rsa)
{
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_exp(m, c, b10rsa->d, b10rsa->n, ctx);
    BN_CTX_free(ctx);
};

int main (int argc, char *argv[])
{
    BOB10_RSA *b10rsa = BOB10_RSA_new();
    BIGNUM *in = BN_new();
    BIGNUM *out = BN_new();

    if(argc == 2){
        if(strncmp(argv[1],"-k",2)){
            PrintUsage();
            return -1;
        }
        BOB10_RSA_KeyGen(b10rsa,1024);
        BN_print_fp(stdout,b10rsa->n);
        printf(" ");
        BN_print_fp(stdout,b10rsa->e);
        printf(" ");
        BN_print_fp(stdout,b10rsa->d);
        printf("\n");
    }else if(argc == 5){
        if(strncmp(argv[1],"-e",2) && strncmp(argv[1],"-d",2)){
            PrintUsage();
            return -1;
        }
        BN_hex2bn(&b10rsa->n, argv[3]);
        BN_hex2bn(&in, argv[4]);
        if(!strncmp(argv[1],"-e",2)){
            BN_hex2bn(&b10rsa->e, argv[2]);
            BOB10_RSA_Enc(out,in, b10rsa);
        }else if(!strncmp(argv[1],"-d",2)){
            BN_hex2bn(&b10rsa->d, argv[2]);
            BOB10_RSA_Dec(out,in, b10rsa);
        }else{
            PrintUsage();
            return -1;
        }
        BN_print_fp(stdout,out);
    }else{
        PrintUsage();
        return -1;
    }

    if(in != NULL) BN_free(in);
    if(out != NULL) BN_free(out);
    if(b10rsa!= NULL) BOB10_RSA_free(b10rsa);

    return 0;
}