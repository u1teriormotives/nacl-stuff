#include "Encrypt.h"

#include <sodium.h>
#include <stddef.h>
#include <string.h>

int encrypt_statement_b64pk(const char* recipient_pk_b64,
                            const unsigned char* statement,
                            size_t statement_len,
                            unsigned char* ciphertext_out) {
  unsigned char recipient_pk[crypto_box_PUBLICKEYBYTES];

  const int b64_variant = sodium_base64_VARIANT_ORIGINAL;

  size_t pk_len = 0;
  if (sodium_base642bin(recipient_pk, sizeof recipient_pk, recipient_pk_b64,
                        strlen(recipient_pk_b64), NULL, &pk_len, NULL,
                        b64_variant)
      != 0) {
    return -1;
  }

  size_t ciphertext_len = crypto_box_SEALBYTES + statement_len;

  if (crypto_box_seal(ciphertext_out, statement, statement_len, recipient_pk)
      != 0) {
    return -2;
  }

  return (int) ciphertext_len;
}
