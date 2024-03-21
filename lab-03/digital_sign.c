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
    BIGNUM *n, *e, *m1, *m2, *b;
    BN_CTX *ctx = BN_CTX_new(); // temporary variable

    // initialize the big numbers
    n = BN_new();
    e = BN_new();
    m1 = BN_new();
    m2 = BN_new();
    b = BN_new();
    
    // define n, e, m1, b
    BN_hex2bn(&n, "A5F2D1A55214C1B80178122F9A039D43EA96CEF33DAD45BA29382AA4DF4936B3D50EEE70E2E5FBE9A0CBE6B442C34282E9D8DDF5D3C1698A3190018F8F8AE4E0B3C8D22E68065D1BB54DE3E7AE216AC74BA303C9CA51DF547FA33ED195ED1BC6FEE6BC45015E83FF50889C62E3378DEAC854283A32C7EF03D65FF7AC16F80CB9C049A61B086634B49350BC0A14B633AF13688AB01F81216A3AF792138B63AE916E22E6588FF139F3BB694F5E2C3E494AF22B9099B7DEDF625DB19F6450A8003A34E76851F74B5C5A28062C1C794E0257289DDD930E779301D53507A7EF7CA1DCF2559C18BD65BB36A05F2F28B683138CB2C020CBAC31E18B29C84FC14BC7CAB7");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&m1, "978d4c25d21aaebe4a4abc04d87f456e643218a8dca7eebc4086a75075346ec5206e351c6e1e93025db36d9378711bf0b70b2266b3debb1d8680938e3e4fd988dfdacce7de7a8698a8abffdc5462a0bdb4ba99e9e9139cf9f27b8f7bc89e7c9bbadcc907eae25861a4c87edf32310298365c4d9eb943329f31164b80c962dc146d86bf84e8d5dd5dd51c102576d86554d4d0172d2eeb4fbe7eddcf136d6bb8dfb8e0b0df2aba5db089b54b54ce205bbbaecb0d8aa814cfda8d44372709e7ff59151e7cb5e19a8122825d3e6fd0e63946008c9db40179d3ac93b6e8845ace9c2746b8ff29f7b439c76c477b89593b918fd8c5493450f60f3f4c3a6cc864651a4f");
    BN_hex2bn(&b, "222a599446d82f5fb1575fb491b071e4ac7b14bd72e0c8af470349f09db95d82"); // certificate body

    // decrypt: m2 = m1^e mod n
    BN_mod_exp(m2, m1, e, n, ctx);
    printBN("m = ", m2);

    BN_free(n);
    BN_free(e);
    BN_free(m1);
    BN_free(m2);
    BN_CTX_free(ctx);

    return 0;
}
