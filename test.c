#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

#include "Encrypt.h"

static void b64_encode(const unsigned char* input, int length) {
  BIO *bio, *b64;
  BUF_MEM* bufferPtr;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(bio, input, length);
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bufferPtr);

  printf("%.*s\n", (int) bufferPtr->length, bufferPtr->data);

  BIO_free_all(bio);
}

int main(void) {
  if (sodium_init() < 0) {
    fprintf(stderr, "libsodium init fail\n");
    exit(EXIT_FAILURE);
  }

  const char* pk = "sRCF2OpB2daFjIKqPEMBw2EUVy9qNlBclgs3Qwp9EAc=";
  unsigned char pt[2048];

  printf("Enter message: ");

  if (fgets((char*) pt, sizeof(pt), stdin) == NULL) { return 1; }

  size_t len = strlen((char*) pt);

  if (len > 0 && pt[len - 1] == '\n') { pt[--len] = '\0'; }

  unsigned char ciphertext[crypto_box_SEALBYTES + len];
  int clen = encrypt_statement_b64pk(pk, pt, len, ciphertext);

  if (clen < 0) exit(2);

  b64_encode(ciphertext, clen);

  exit(EXIT_SUCCESS);
}
