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
BIGNUM* calcTotient(BIGNUM*, BIGNUM*);
BIGNUM* encrypt(char*, struct Public_Key *);
char* decrypt(BIGNUM*, struct Private_Key *);
void task3(void);
void task5(void);
BIGNUM* sign(char*, struct Private_Key *);
int verifySignature(char*, char*, struct Public_Key *);
int verifySignatureHash(char*, char*, struct Public_Key *);

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
    char* decrypted = NULL;

    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");

    BN_mul(n, p, q, ctx);

    totient = calcTotient(p, q);

    /*
        Task 1
        Calculate private key
    */
    BN_mod_inverse(d, e, totient, ctx);

    printBN("Task 1\n\nPrivate key is", d);

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

    c = encrypt("A top secret!", &pub);
    printBN("\nTask2\nCiphered text is", c);

    /*
        Task 3
        Decrypt a given message
    */
    task3();

    /*
        Task 4
        Sign a message
    */
    BIGNUM* s1 = sign("I owe you $2000.", &pem);
    BIGNUM* s2 = sign("I owe you $3000.", &pem);
    printf("\nTask4\n");
    printBN("Signed message 1 =", s1);
    printBN("Signed message 2 =", s2);

    /*
        Task 5
        Verify the message
    */

    // Verify previous signatures
    int signatureValid;

    signatureValid = verifySignature("55A4E7F17F04CCFE2766E1EB32ADDBA890BBE92A6FBE2D785ED6E73CCB35E4CB", "I owe you $3000.", &pub);
    printf("The signature %s\n", (signatureValid)? "is valid":"is not valid" );
    signatureValid = verifySignature("55A4E7F17F04CCFE2766E1EB32ADDBA890BBE92A6FBE2D785ED6E73CCB35E4CB", "I owe you $2000.", &pub);
    printf("The signature %s\n", (signatureValid)? "is valid":"is not valid" );
    
    // Verify task's signature
    task5();

    /*
        Task 6
    */
    BIGNUM *n_6 = BN_new();
    BIGNUM *e_6 = BN_new();
    char *signat = "84a89a11a7d8bd0b267e52247bb2559dea30895108876fa9ed10ea5b3e0bc72d47044edd4537c7cabc387fb66a1c65426a73742e5a9785d0cc92e22e3889d90d69fa1b9bf0c16232654f3d98dbdad666da2a5656e31133ece0a5154cea7549f45def15f5121ce6f8fc9b04214bcf63e77cfcaadcfa43d0c0bbf289ea916dcb858e6a9fc8f994bf553d4282384d08a4a70ed3654d3361900d3f80bf823e11cb8f3fce7994691bf2da4bc897b811436d6a2532b9b2ea2262860da3727d4fea573c653b2f2773fc7c16fb0d03a40aed01aba423c68d5f8a21154292c034a220858858988919b11e20ed13205c045564ce9db365fdf68f5e99392115e271aa6a8882";
    char* body = "902677e610fedcdd34780e359692eb7bd199af35115105636aeb623f9e4dd053";
    BN_hex2bn(&n_6, "B6E02FC22406C86D045FD7EF0A6406B27D22266516AE42409BCEDC9F9F76073EC330558719B94F940E5A941F5556B4C2022AAFD098EE0B40D7C4D03B72C8149EEF90B111A9AED2C8B8433AD90B0BD5D595F540AFC81DED4D9C5F57B786506899F58ADAD2C7051FA897C9DCA4B182842DC6ADA59CC71982A6850F5E44582A378FFD35F10B0827325AF5BB8B9EA4BD51D027E2DD3B4233A30528C4BB28CC9AAC2B230D78C67BE65E71B74A3E08FB81B71616A19D23124DE5D79208AC75A49CBACD17B21E4435657F532539D11C0A9A631B199274680A37C2C25248CB395AA2B6E15DC1DDA020B821A293266F144A2141C7ED6D9BF2482FF303F5A26892532F5EE3");
    BN_hex2bn(&e_6, "010001");

    BIGNUM *s_6 = BN_new();
    BIGNUM *new_h = BN_new();

    BN_hex2bn(&s_6, signat);

    BN_mod_exp(new_h, s_6, e_6, n_6, ctx);
    char * new_h_s = BN_bn2hex(new_h);
    
    printf("\nTask 6\nThis was the hash derived from the signature %s\n", new_h_s);
    printf("\nAnd this was the body from the certificate: %s\n", body);
    BN_CTX_free(ctx);
    OPENSSL_free(new_h_s);
    return 0;
}

int verifySignature(char* signature, char* message, struct Public_Key * pub)
{
    BN_CTX *ctx = BN_CTX_new();
    // Returns 0 if the signature is corrupted
    // Returns 1 if signature is OK
    BIGNUM *s = BN_new();
    BIGNUM *new_h = BN_new();
    char* orig_h = atoHex(message);
    BN_hex2bn(&s, signature);

    BN_mod_exp(new_h, s, pub->e, pub->n, ctx);
    char * new_h_s = BN_bn2hex(new_h);

    int res = !strcmp(orig_h, new_h_s);
    BN_CTX_free(ctx);
    OPENSSL_free(new_h_s);
    free(orig_h);

    if (res) {
        return 1;
    } else {
        return 0;
    }
}

void task5() {
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    char *s = "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F";

    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BN_hex2bn(&e, "010001");

    struct Public_Key pub = {
        e = e,
        n = n
    };

    int signatureValid = verifySignatureHash(s, "4C61756E63682061206D697373696C652E", &pub);
    if (signatureValid) {
        printf("Alice's signature is valid\n");
    } else {
        printf("Alice's signature is not valid\n");
    }
}

int verifySignatureHash(char* signature, char* orig_h, struct Public_Key * pub)
{
    BN_CTX *ctx = BN_CTX_new();
    // Returns 0 if the signature is corrupted
    // Returns 1 if signature is OK
    BIGNUM *s = BN_new();
    BIGNUM *new_h = BN_new();

    BN_hex2bn(&s, signature);

    BN_mod_exp(new_h, s, pub->e, pub->n, ctx);
    char * new_h_s = BN_bn2hex(new_h);

    int res = !strcmp(orig_h, new_h_s);
    OPENSSL_free(new_h_s);

    BN_CTX_free(ctx);

    if (res) {
        return 1;
    } else {
        return 0;
    }
}

BIGNUM* sign(char* message, struct Private_Key * pem)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *h = BN_new();
    BIGNUM *s = BN_new();
    char* hexString = NULL;

    hexString = atoHex(message);
    BN_hex2bn(&h, hexString);
    
    free(hexString);
    BN_mod_exp(s, h, pem->d, pem->n, ctx);

    BN_CTX_free(ctx);

    return s;
}

void task3()
{
    BIGNUM *c = BN_new();
    BIGNUM *n_2 = BN_new();
    BIGNUM *d_2 = BN_new();
    BN_hex2bn(&n_2, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d_2, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    struct Private_Key pem = {
        d_2,
        n_2
    };

    char* ciphered = "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F";
    BN_hex2bn(&c, ciphered);
    char *decrypted = decrypt(c, &pem);
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

BIGNUM* calcTotient(BIGNUM *p, BIGNUM *q)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *totient = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *p_1 = BN_new();
    BIGNUM *q_1 = BN_new();

    BN_dec2bn(&one, "1");

    BN_sub(p_1, p, one);
    BN_sub(q_1, q, one);

    BN_mul(totient, p_1, q_1, ctx);

    BN_CTX_free(ctx);

    return totient;
}

BIGNUM* encrypt(char* message, struct Public_Key * pub)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *m = BN_new();
    BIGNUM *c = BN_new();
    char* hexString = NULL;
    
    hexString = atoHex(message);

    BN_hex2bn(&m, hexString);
    BN_mod_exp(c, m, pub->e, pub->n, ctx);

    free(hexString);
    BN_CTX_free(ctx);
    return c;
}

char* decrypt(BIGNUM* c, struct Private_Key * pem)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *m = BN_new();
    char* decrypted = NULL;

    BN_mod_exp(m, c, pem->d, pem->n, ctx);

    decrypted = BN_bn2hex(m);

    char *ascii = hexToA(decrypted);
    OPENSSL_free(decrypted);

    BN_CTX_free(ctx);

    return ascii;
}