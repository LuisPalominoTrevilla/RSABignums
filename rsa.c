#include <stdio.h>
#include<openssl/bn.h>

#define NBITS 256

// gcc bignum.c -o bignum -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include -lcrypto

void printBN(char *msg, BIGNUM *a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

BIGNUM* calcTotient(BIGNUM *p, BIGNUM *q, BN_CTX *ctx)
{
    BIGNUM *totient = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *p_1 = BN_new();
    BIGNUM *q_1 = BN_new();

    BN_dec2bn(&one, "1");

    BN_sub(p_1, p, one);
    BN_sub(q_1, q, one);

    BN_mul(totient, p_1, q_1, ctx);

    return totient;
}

struct Public_Key {
    BIGNUM* e;
    BIGNUM* n;
};

struct Private_Key {
    BIGNUM* d;
    BIGNUM* n;
};

int main()
{
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();

    BIGNUM *totient;

    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");

    BN_mul(n, p, q, ctx);

    // Calc totient of n
    totient = calcTotient(p, q, ctx);

    BN_mod_inverse(d, e, totient, ctx);

    struct Public_Key pub = {
        e = e,
        n = n
    };

    struct Private_Key priv = {
        d = d,
        n = n
    }

    return 0;
}