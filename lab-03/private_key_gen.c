/* private_key_gen.c */
#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
    // Use BN_bn2hex(a) for hex string
    // Use BN_bn2dec(a) for decimal string
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main ()
{
    // temporary variable
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *z = BN_new();
    BIGNUM *d = BN_new();

    // initialize p, q, e
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");

    // calculating n
    BN_mul(n, p, q, ctx);

    BIGNUM *sub_p = BN_new();
    BIGNUM *sub_q = BN_new();
    BIGNUM *i = BN_new();
    BN_dec2bn(&i, "1");
    
    // calculating (p-1)
    BN_sub(sub_p, p, i);

    // calculating (q-1)
    BN_sub(sub_q, q, i);

    // calculating z
    BN_mul(z, sub_p, sub_q, ctx);

    printBN("n = ", n);
    printBN("z = ", z);

    // calculating d
    BN_mod_inverse(d, e, z, ctx);

    printBN("d = ", d);
    printBN("i = ", i);
    
    return 0;
}
