#include <stdio.h>
#include<openssl/bn.h>
#include <string.h>

#define NBITS 256

// gcc bignum.c -o bignum -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include -lcrypto

struct Public_Key {
    BIGNUM* e;
    BIGNUM* n;
};

struct Private_Key {
    BIGNUM* d;
    BIGNUM* n;
};

int getHexVal(char c)
{
    if(c >= '0' && c<= '9')
        return c - '0';
    else if(c >= 'a' && c<= 'f')
        return c - 'a' + 10;
    else if(c >= 'A' && c<= 'F')
        return c - 'A' + 10;
    else
        return -1;
}

void PrintBN(char *msg, BIGNUM *a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

char* AtoHex(char* asciiText)
{
    int i;
    int n;
    
    n = strlen(asciiText);
    char* out = (char*) malloc(sizeof(char) * n);
    for(i = 0; i<n; i++){
        sprintf(out+i*2, "%02X", asciiText[i]);
    }
    return out;
}

char* HexToA(char* hexText)
{
    int n = strlen(hexText);

    char* asciiStr = (char*) malloc(sizeof(char) * (n/2 + 1));

    for(int i = 0; i < n; i +=2) {
        asciiStr[i/2] = (getHexVal(hexText[i])*16 + getHexVal(hexText[i+1]));
    }

    return asciiStr;
}

BIGNUM* CalcTotient(BIGNUM *p, BIGNUM *q, BN_CTX *ctx)
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

BIGNUM* Encrypt(char* message, struct Public_Key pub, BN_CTX* ctx)
{
    BIGNUM *m = BN_new();
    BIGNUM *c = BN_new();
    char* hexString;
    
    hexString = AtoHex(message);

    BN_hex2bn(&m, hexString);
    BN_mod_exp(c, m, pub.e, pub.n, ctx);

    free(hexString);
    return c;
}

char* Decrypt(BIGNUM* c, struct Private_Key pem, BN_CTX* ctx)
{
    BIGNUM *m = BN_new();
    char* decrypted;

    BN_mod_exp(m, c, pem.d, pem.n, ctx);

    decrypted = BN_bn2hex(m);

    char *ascii = HexToA(decrypted);
    OPENSSL_free(decrypted);

    return ascii;
}

int main()
{
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();

    BIGNUM *c;
    BIGNUM *totient;
    char* decrypted;

    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");

    BN_mul(n, p, q, ctx);

    // Calc totient of n
    totient = CalcTotient(p, q, ctx);

    BN_mod_inverse(d, e, totient, ctx);

    struct Public_Key pub = {
        e = e,
        n = n
    };

    struct Private_Key pem = {
        d = d,
        n = n
    };

    // Encrypt plain text
    c = Encrypt("A top secret!", pub, ctx);

    // Decrypt cyphertext
    decrypted = Decrypt(c, pem, ctx);
    printf("%s", decrypted);

    free(decrypted);
    return 0;
}