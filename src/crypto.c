#include <openssl/evp.h>

#include <string.h>
#include <assert.h>

#include "../include/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif


EXPORT_FUNC int CE_AES_encrypt(
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
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
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


EXPORT_FUNC int CE_AES_decrypt(
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
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
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


#ifdef __cplusplus
}
#endif