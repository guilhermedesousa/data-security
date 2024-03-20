/* private_key_gen.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main ()
{
    BIGNUM *n, *e, *d, *m1, *c, *m2;
    BN_CTX *ctx = BN_CTX_new(); // temporary variable

    // initialize the big numbers
    n = BN_new();
    e = BN_new();
    d = BN_new();
    m1 = BN_new();
    c = BN_new();
    m2 = BN_new();
    
    // define n, e, d, m1
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&m1, "4375696461646F3A2070726F6772616D6120696E73656775726F21");

    // encrypt: c = m1^e mod n
    BN_mod_exp(c, m1, e, n, ctx);
    printBN("c = ", c);

    // decrypt: m2 = c^d mod n
    BN_mod_exp(m2, c, d, n, ctx);
    printBN("m = ", m2);

    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(m1);
    BN_free(c);
    BN_free(m2);
    BN_CTX_free(ctx);

    return 0;
}
