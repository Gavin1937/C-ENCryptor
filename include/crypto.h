#ifndef CRYPTO_H
#define CRYPTO_H


#define AES_BLOCK_SIZE 16
#define AES_CBC_KEY_LENGTH 16 // 128 bits
#define AES_CBC_IV_LENGTH 16 // 128 bits
#define NO_PADDING 0
#define PKCS7_PADDING 1
#define ENCR_PBKDF2_ROUNDS 4096


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


#endif