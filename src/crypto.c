
#include <stdlib.h>
#include <string.h>

#include "../include/C-ENCryptor/crypto.h"
#include "../include/C-ENCryptor/constants.h"
#include "../include/C-ENCryptor/error_handle.h"


void CE_OSSL_AES_encr_init(
    CE_OSSL_AES_CTX* ctx,
    const unsigned char* key, const unsigned char* iv,
    const int padding
)
{
    // set key, iv, & padding
    memcpy(ctx->key, key, AES_CBC_KEY_LENGTH);
    if (iv == NULL) {
        memset(ctx->iv, 0, AES_CBC_IV_LENGTH);
    }
    else {
        memcpy(ctx->iv, iv, AES_CBC_IV_LENGTH);
    }
    ctx->padding = padding == 0 ? NO_PADDING : PKCS7_PADDING;
    
    // setup cipher
#ifdef CE_OSSL_COMPATIBLE_MODE
    condition_check(
        (0 != AES_set_encrypt_key(ctx->key, 128, &(ctx->ctx))),
        "AES_set_encrypt_key failed\n"
    );
#else
    ctx->ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx->ctx, ctx->padding);
    condition_check(
        (1 != EVP_EncryptInit_ex(ctx->ctx, EVP_aes_128_cbc(), NULL, ctx->key, ctx->iv)),
        "EVP_EncryptInit_ex failed\n"
    );
#endif
}

int CE_OSSL_AES_encr_update(
    CE_OSSL_AES_CTX* ctx,
    const unsigned char* data_in, unsigned char* data_out,
    const int data_length
)
{
    // check data_length
    condition_check(
        (data_length % AES_BLOCK_SIZE != 0),
        "data_length is not multiple of 16\n"
    );
    
    // encrypt
#ifdef CE_OSSL_COMPATIBLE_MODE
    AES_cbc_encrypt(data_in, data_out, data_length, &(ctx->ctx), ctx->iv, AES_ENCRYPT);
    
    return data_length;
#else
    int chunk_len = 0, output_len = 0;
    condition_check(
        (1 != EVP_EncryptUpdate(ctx->ctx, data_out, &chunk_len, data_in, data_length)),
        "EVP_EncryptUpdate failed\n"
    );
    output_len += chunk_len;
    condition_check(
        (1 != EVP_EncryptFinal_ex(ctx->ctx, data_out + chunk_len, &chunk_len)),
        "EVP_EncryptFinal_ex failed\n"
    );
    output_len += chunk_len;
    
    return output_len;
#endif
}

void CE_OSSL_AES_encr_finish(CE_OSSL_AES_CTX* ctx)
{
#ifdef CE_OSSL_COMPATIBLE_MODE
#else
    EVP_CIPHER_CTX_free(ctx->ctx);
#endif
}

void CE_OSSL_AES_decr_init(
    CE_OSSL_AES_CTX* ctx,
    const unsigned char* key, const unsigned char* iv,
    const int padding
)
{
    // set key, iv, & padding
    memcpy(ctx->key, key, AES_CBC_KEY_LENGTH);
    if (iv == NULL) {
        memset(ctx->iv, 0, AES_CBC_IV_LENGTH);
    }
    else {
        memcpy(ctx->iv, iv, AES_CBC_IV_LENGTH);
    }
    ctx->padding = padding == 0 ? NO_PADDING : PKCS7_PADDING;
    
    // setup cipher
#ifdef CE_OSSL_COMPATIBLE_MODE
    condition_check(
        (0 != AES_set_decrypt_key(ctx->key, 128, &(ctx->ctx))),
        "AES_set_decrypt_key failed\n"
    );
#else
    ctx->ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx->ctx, ctx->padding);
    condition_check(
        (1 != EVP_DecryptInit_ex(ctx->ctx, EVP_aes_128_cbc(), NULL, ctx->key, ctx->iv)),
        "EVP_DecryptInit_ex failed\n"
    );
#endif
}

int CE_OSSL_AES_decr_update(
    CE_OSSL_AES_CTX* ctx,
    const unsigned char* data_in, unsigned char* data_out,
    const int data_length
)
{
    // check data_length
    condition_check(
        (data_length % AES_BLOCK_SIZE != 0),
        "data_length is not multiple of 16\n"
    );
    
    // decrypt
#ifdef CE_OSSL_COMPATIBLE_MODE
    AES_cbc_encrypt(data_in, data_out, data_length, &(ctx->ctx), ctx->iv, AES_DECRYPT);
    
    return data_length;
#else
    int chunk_len = 0, output_len = 0;
    condition_check(
        (1 != EVP_DecryptUpdate(ctx->ctx, data_out, &chunk_len, data_in, data_length)),
        "EVP_DecryptUpdate failed\n"
    );
    output_len += chunk_len;
    condition_check(
        (1 != EVP_DecryptFinal_ex(ctx->ctx, data_out + chunk_len, &chunk_len)),
        "EVP_DecryptFinal_ex failed\n"
    );
    output_len += chunk_len;
    
    return output_len;
#endif
}

void CE_OSSL_AES_decr_finish(CE_OSSL_AES_CTX* ctx)
{
#ifdef CE_OSSL_COMPATIBLE_MODE
#else
    EVP_CIPHER_CTX_free(ctx->ctx);
#endif
}

int CE_AES_encrypt(
    const unsigned char* data_in, unsigned char* data_out, const int data_length,
    const unsigned char* key, const unsigned char* iv, const int padding
)
{
    CE_OSSL_AES_CTX ctx;
    
    CE_OSSL_AES_encr_init(&ctx, key, iv, padding);
    
    int result = CE_OSSL_AES_encr_update(&ctx, data_in, data_out, data_length);
    
    CE_OSSL_AES_encr_finish(&ctx);
    
    return result;
}


int CE_AES_decrypt(
    const unsigned char* data_in, unsigned char* data_out, const int data_length,
    const unsigned char* key, const unsigned char* iv, const int padding
)
{
    CE_OSSL_AES_CTX ctx;
    
    CE_OSSL_AES_decr_init(&ctx, key, iv, padding);
    
    int result = CE_OSSL_AES_decr_update(&ctx, data_in, data_out, data_length);
    
    CE_OSSL_AES_decr_finish(&ctx);
    
    return result;
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
    memcpy((encr_buffer+0), encr_position, 8);
    memcpy((encr_buffer+8), encr_size, 8);
    memcpy((encr_buffer+16), encr_reserved_1, 8);
    memcpy((encr_buffer+24), encr_reserved_2, 8);
    
    CE_AES_decrypt(encr_buffer, decr_buffer, 32, master_key, NULL, NO_PADDING);
    
    memcpy(decr_position, (decr_buffer+0), 8);
    memcpy(decr_size, (decr_buffer+8), 8);
    memcpy(decr_reserved_1, (decr_buffer+16), 8);
    memcpy(decr_reserved_2, (decr_buffer+24), 8);
}

