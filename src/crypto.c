#include <openssl/evp.h>
#include <openssl/sha.h>

#include <string.h>
#include <assert.h>

#include "../include/crypto.h"
#include "../include/constants.h"


int CE_AES_encrypt(
    const unsigned char* data_in, unsigned char* data_out, const int data_length,
    const unsigned char* key, const unsigned char* iv, const int padding
)
{
    // check data_length
    assert(data_length % AES_BLOCK_SIZE == 0);
    
    // set iv & padding
    unsigned char tmp_iv[AES_CBC_IV_LENGTH];
    if (iv == NULL)
        memset(tmp_iv, 0, AES_CBC_IV_LENGTH);
    else
        memcpy_s(tmp_iv, AES_CBC_IV_LENGTH, iv, AES_CBC_IV_LENGTH);
    int pad = padding == 0 ? NO_PADDING : PKCS7_PADDING;
    
    // setup cipher
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, pad);
    assert(1 == EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, tmp_iv));
    
    // encrypt
    int chunk_len = 0, output_len = 0;
    assert(1 == EVP_EncryptUpdate(ctx, data_out, &chunk_len, data_in, data_length));
    output_len += chunk_len;
    assert(1 == EVP_EncryptFinal_ex(ctx, data_out + chunk_len, &chunk_len));
    output_len += chunk_len;
    
    // finish
    EVP_CIPHER_CTX_free(ctx);    
    return output_len;
}


int CE_AES_decrypt(
    const unsigned char* data_in, unsigned char* data_out, const int data_length,
    const unsigned char* key, const unsigned char* iv, const int padding
)
{
    // check data_length
    assert(data_length % AES_BLOCK_SIZE == 0);
    
    // set iv & padding
    unsigned char tmp_iv[AES_CBC_IV_LENGTH];
    if (iv == NULL)
        memset(tmp_iv, 0, AES_CBC_IV_LENGTH);
    else
        memcpy_s(tmp_iv, AES_CBC_IV_LENGTH, iv, AES_CBC_IV_LENGTH);
    int pad = padding == 0 ? NO_PADDING : PKCS7_PADDING;
    
    // setup cipher
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, pad);
    assert(1 == EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, tmp_iv));
    
    // decrypt
    int chunk_len = 0, output_len = 0;
    assert(1 == EVP_DecryptUpdate(ctx, data_out, &chunk_len, data_in, data_length));
    output_len += chunk_len;
    assert(1 == EVP_DecryptFinal_ex(ctx, data_out + chunk_len, &chunk_len));
    output_len += chunk_len;
    
    // finish
    EVP_CIPHER_CTX_free(ctx);    
    return output_len;
}

int key_size_in_bytes(uint8_t aes_key_bits)
{
    int key_size = 0;
    if (aes_key_bits <= 128)
        key_size = 16;
    else if (aes_key_bits <= 192)
        key_size = 24;
    else
        key_size = 32;
    return key_size;
}

void derive_master_key(
    unsigned char* key_out,
    const unsigned char* password, const int password_size,
    const unsigned char* salt, const int salt_size,
    int aes_key_bit
)
{
    int key_size = key_size_in_bytes(aes_key_bit);
    
    PKCS5_PBKDF2_HMAC(
        password, password_size,
        salt, salt_size,
        ENCR_PBKDF2_ROUNDS, EVP_sha256(),
        AES_CBC_KEY_LENGTH, key_out
    );
}

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
)
{
    unsigned char encr_buffer[32];
    unsigned char decr_buffer[32];
    memcpy_s((encr_buffer+0), 8, encr_position, 8);
    memcpy_s((encr_buffer+8), 8, encr_size, 8);
    memcpy_s((encr_buffer+16), 8, encr_reserved_1, 8);
    memcpy_s((encr_buffer+24), 8, encr_reserved_2, 8);
    
    CE_AES_decrypt(encr_buffer, decr_buffer, 32, master_key, NULL, NO_PADDING);
    
    memcpy_s(decr_position, 8, (decr_buffer+0), 8);
    memcpy_s(decr_size, 8, (decr_buffer+8), 8);
    memcpy_s(decr_reserved_1, 8, (decr_buffer+16), 8);
    memcpy_s(decr_reserved_2, 8, (decr_buffer+24), 8);
}

