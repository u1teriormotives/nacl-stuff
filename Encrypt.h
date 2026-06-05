#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <stddef.h>

int encrypt_statement_b64pk(const char* recipient_pk_b64,
                            const unsigned char* statement,
                            size_t statement_len,
                            unsigned char* ciphertext_out);

#endif
