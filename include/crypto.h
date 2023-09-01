#ifndef CRYPTO_H
#define CRYPTO_H

#include "macros.h"


#define AES_BLOCK_SIZE 16
#define AES_CBC_KEY_LENGTH 16 // 128 bits
#define AES_CBC_IV_LENGTH 16 // 128 bits
#define NO_PADDING 0
#define PKCS7_PADDING 1


EXPORT_FUNC int CE_AES_encrypt(
    const unsigned char* data_in, unsigned char* data_out, const int data_length,
    const unsigned char* key, const unsigned char* iv, const int padding
);

EXPORT_FUNC int CE_AES_decrypt(
    const unsigned char* data_in, unsigned char* data_out, const int data_length,
    const unsigned char* key, const unsigned char* iv, const int padding
);

#endif