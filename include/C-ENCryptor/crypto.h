#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>

int CE_AES_encrypt(
    const unsigned char* data_in, unsigned char* data_out, const int data_length,
    const unsigned char* key, const unsigned char* iv, const int padding
);

int CE_AES_decrypt(
    const unsigned char* data_in, unsigned char* data_out, const int data_length,
    const unsigned char* key, const unsigned char* iv, const int padding
);

void derive_master_key(
    unsigned char* key_out,
    const unsigned char* password, const int password_size,
    const unsigned char* salt, const int salt_size,
    int aes_key_bit
);

int key_size_in_bytes(uint8_t aes_key_bits);

void decrypt_locator(
    const unsigned char* master_key,
    const uint64_t* encr_position,
    const uint64_t* encr_size,
    const uint64_t* encr_reserved_1,
    const uint64_t* encr_reserved_2,
    uint64_t* decr_position,
    uint64_t* decr_size,
    uint64_t* decr_reserved_1,
    uint64_t* decr_reserved_2
);

#endif