#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
  if (sodium_init() < 0) { return 1; }

  unsigned char pk[crypto_kx_PUBLICKEYBYTES];
  unsigned char sk[crypto_kx_SECRETKEYBYTES];

  crypto_kx_keypair(pk, sk);

  char pk_b64[sodium_base64_ENCODED_LEN(crypto_kx_PUBLICKEYBYTES,
                                        sodium_base64_VARIANT_ORIGINAL)];
  char sk_b64[sodium_base64_ENCODED_LEN(crypto_kx_SECRETKEYBYTES,
                                        sodium_base64_VARIANT_ORIGINAL)];

  sodium_bin2base64(pk_b64, sizeof pk_b64, pk, sizeof pk,
                    sodium_base64_VARIANT_ORIGINAL);

  sodium_bin2base64(sk_b64, sizeof sk_b64, sk, sizeof sk,
                    sodium_base64_VARIANT_ORIGINAL);

  printf("Secret Key: %s\n", sk_b64);
  printf("Public Key: %s\n", pk_b64);
  sodium_memzero(sk, sizeof sk);
  sodium_memzero(sk_b64, sizeof sk_b64);

  exit(EXIT_SUCCESS);
}
