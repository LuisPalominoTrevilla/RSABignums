#include <stdio.h>
#include<openssl/bn.h>
#include <string.h>

#define NBITS 256

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
void task5(BN_CTX*);
BIGNUM* sign(char*, struct Private_Key, BN_CTX*);
int verifySignature(char*, char*, struct Public_Key, BN_CTX*);

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

    printBN("TASK 1\n\nPrivate key is", d);

    /*
        Task 2
        Encrypt a message
    */
    BIGNUM *n_2 = BN_new();
    BIGNUM *e_2 = BN_new();
    BIGNUM *d_2 = BN_new();
    BN_hex2bn(&n_2, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e_2, "010001");
    BN_hex2bn(&d_2, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    struct Public_Key pub = {
        e = e_2,
        n = n_2
    };

    struct Private_Key pem = {
        d = d_2,
        n = n_2
    };

    c = encrypt("A top secret!", pub, ctx);
    printBN("Task2\nCiphered text is", c);

    /*
        Task 3
        Decrypt a given message
    */
    task3(pem, ctx);

    /*
        Task 4
        Sign a message
    */
    BIGNUM* s1 = sign("I owe you $2000.", pem, ctx);
    BIGNUM* s2 = sign("I owe you $3000.", pem, ctx);
    printf("\nTask4\n");
    printBN("Signed message 1 =", s1);
    printBN("Signed message 2 =", s2);

    /*
        Task 5
        Verify the message
    */

    // Verify previous signatures
    int signatureValid;

    signatureValid = verifySignature("55A4E7F17F04CCFE2766E1EB32ADDBA890BBE92A6FBE2D785ED6E73CCB35E4CB", "I owe you $3000.", pub, ctx);
    printf("The signature %s\n", (signatureValid)? "is valid":"is not valid" );
    signatureValid = verifySignature("55A4E7F17F04CCFE2766E1EB32ADDBA890BBE92A6FBE2D785ED6E73CCB35E4CB", "I owe you $2000.", pub, ctx);
    printf("The signature %s\n", (signatureValid)? "is valid":"is not valid" );
    
    // Verify task's signature
    task5(ctx);

    return 0;
}

void task5(BN_CTX* ctx) {
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    char *s = "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F";

    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BN_hex2bn(&e, "010001");

    struct Public_Key pub = {
        e = e,
        n = n
    };

    int signatureValid = verifySignature(s, "Launch a missle.", pub, ctx);
    if (signatureValid) {
        printf("Alice's signature is valid");
    } else {
        printf("Alice's signature is not valid");
    }
}

int verifySignature(char* signature, char* message, struct Public_Key pub, BN_CTX* ctx)
{
    // Returns 0 if the signature is corrupted
    // Returns 1 if signature is OK
    BIGNUM *s = BN_new();
    BIGNUM *new_h = BN_new();
    char* orig_h;
    orig_h = atoHex(message);
    BN_hex2bn(&s, signature);

    BN_mod_exp(new_h, s, pub.e, pub.n, ctx);
    char * new_h_s = BN_bn2hex(new_h);

    if (!strcmp(orig_h, new_h_s)) {
        free(orig_h);
        return 1;
    } else {
        free(orig_h);
        return 0;
    }
}

BIGNUM* sign(char* message, struct Private_Key pem, BN_CTX* ctx)
{
    BIGNUM *h = BN_new();
    BIGNUM *s = BN_new();
    char* hexString;

    hexString = atoHex(message);
    BN_hex2bn(&h, hexString);
    free(hexString);

    BN_mod_exp(s, h, pem.d, pem.n, ctx);

    return s;
}

void task3(struct Private_Key pem, BN_CTX* ctx)
{
    BIGNUM *c = BN_new();

    char* ciphered = "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F";
    BN_hex2bn(&c, ciphered);
    char *decrypted = decrypt(c, pem, ctx);
    printf("\nTask3\nDecrypted plain text is: %s\n", decrypted);

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