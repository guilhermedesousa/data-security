/* private_key_gen.c */
#include <stdio.h>
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
    BIGNUM *p, *q, *e, *n, *z, *d, *check;
    BN_CTX *ctx = BN_CTX_new(); // temporary variable

    // initialize the big numbers
    p = BN_new();
    q = BN_new();
    e = BN_new();
    n = BN_new();
    z = BN_new();
    d = BN_new();
    check = BN_new();

    // define p, q, e
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");

    // calculate n = p * q
    BN_mul(n, p, q, ctx);

    // calculate z = (p-1) * (q-1)
    BN_sub_word(p, 1);
    BN_sub_word(q, 1);
    BN_mul(z, p, q, ctx);

    printBN("n = ", n);
    printBN("z = ", z);

    // calculate d = e^(-1) mod z
    BN_mod_inverse(d, e, z, ctx);

    printBN("d = ", d);

    // verify if e * d mod z = 1
    BN_mod_mul(check, e, d, z, ctx);
    
    if (BN_cmp(check, BN_value_one()) == 0) {
        printf("d is correct.\n");
    } else {
        printf("d is incorrect.\n");
    }

    // free memory
    BN_free(p);
    BN_free(q);
    BN_free(e);
    BN_free(n);
    BN_free(z);
    BN_free(d);
    BN_free(check);
    BN_CTX_free(ctx);
    
    return 0;
}
