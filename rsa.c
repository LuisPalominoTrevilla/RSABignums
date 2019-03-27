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

int getHexVal(char);
void printBN(char*, BIGNUM*);
char* atoHex(char*);
char* hexToA(char*);
BIGNUM* calcTotient(BIGNUM*, BIGNUM*, BN_CTX*);
BIGNUM* encrypt(char*, struct Public_Key, BN_CTX*);
char* decrypt(BIGNUM*, struct Private_Key, BN_CTX*);
void task3(struct Private_Key, BN_CTX*);

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

    totient = calcTotient(p, q, ctx);

    /*
        Task 1
        Calculate private key
    */
    BN_mod_inverse(d, e, totient, ctx);

    struct Public_Key pub = {
        e = e,
        n = n
    };

    struct Private_Key pem = {
        d = d,
        n = n
    };

    /*
        Task 2
        Encrypt a message
    */
    c = encrypt("A top secret!", pub, ctx);
    printBN("Ciphered text is", c);

    /*
        Task 3
        Decrypt a given message
    */
    task3(pem, ctx);
    return 0;
}

void task3(struct Private_Key pem, BN_CTX* ctx)
{
    BIGNUM *c = BN_new();

    char* ciphered = "90A81343DFE08415EDF79337CDE00457BAB56AFFA1B0CE5647BF9025665B396A";
    BN_hex2bn(&c, ciphered);
    char *decrypted = decrypt(c, pem, ctx);
    printf("Task 3 decrypted plain text is: %s\n", decrypted);

    free(decrypted);
}

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

void printBN(char *msg, BIGNUM *a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

char* atoHex(char* asciiText)
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

char* hexToA(char* hexText)
{
    int n = strlen(hexText);

    char* asciiStr = (char*) malloc(sizeof(char) * (n/2 + 1));

    for(int i = 0; i < n; i +=2) {
        asciiStr[i/2] = (getHexVal(hexText[i])*16 + getHexVal(hexText[i+1]));
    }

    return asciiStr;
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

BIGNUM* encrypt(char* message, struct Public_Key pub, BN_CTX* ctx)
{
    BIGNUM *m = BN_new();
    BIGNUM *c = BN_new();
    char* hexString;
    
    hexString = atoHex(message);

    BN_hex2bn(&m, hexString);
    BN_mod_exp(c, m, pub.e, pub.n, ctx);

    free(hexString);
    return c;
}

char* decrypt(BIGNUM* c, struct Private_Key pem, BN_CTX* ctx)
{
    BIGNUM *m = BN_new();
    char* decrypted;

    BN_mod_exp(m, c, pem.d, pem.n, ctx);

    decrypted = BN_bn2hex(m);

    char *ascii = hexToA(decrypted);
    OPENSSL_free(decrypted);

    return ascii;
}