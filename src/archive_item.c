
#include "../include/C-ENCryptor/archive_item.h"
#include "../include/C-ENCryptor/util.h"
#include "../include/C-ENCryptor/error_handle.h"
#include "../include/C-ENCryptor/crypto.h"
#include "../include/C-ENCryptor/constants.h"

#include <stdlib.h>
#include <string.h>
#include <zlib/zlib.h>
#include <openssl/evp.h>
#include <openssl/sha.h>


EXPORT_SYMBOL void CEArchiveItem_init(
    FILE* fp,
    uint64_t start,
    uint64_t size,
    uint8_t aes_key_bits,
    const unsigned char* master_key,
    bool hmac,
    CEArchiveItem* item
)
{
    fseek(fp, (long)start, SEEK_SET);
    
    // reading current item's key & iv
    int key_iv_len = decrypt_key_iv(
        fp,
        start,
        aes_key_bits,
        master_key,
        hmac,
        item->item_aes_iv,
        item->item_aes_key,
        item->item_hmac_key
    );
    
    // read file record
    item->file_size = 0;
    item->file_compressed_size = 0;
    
    read_item_header_ret ret = read_item_header(
        fp,
        start,
        key_iv_len,
        item->item_aes_key,
        item->item_aes_iv,
        item
    );
    item->header_size = ret.header_size;
    item->header_padding_len = ret.header_padding_len;
}


EXPORT_SYMBOL void CEArchiveItem_decrypt(
    CEArchiveItem* item,
    FILE* fp,
    FILE* out_fp,
    uint8_t aes_key_bits,
    const unsigned char* master_key,
    bool hmac
)
{
    fseek(fp, (long)item->file_start_location, SEEK_SET);
    
    uint64_t file_start = item->file_start_location;
    uint64_t file_size = 0;
    if (item->file_compressed_size == 0)
        file_size = item->file_size;
    else
        file_size = item->file_compressed_size;
    
    // reading current file's key & iv
    unsigned char file_hmac_key[AES_CBC_IV_LENGTH];
    unsigned char file_aes_iv[AES_CBC_KEY_LENGTH];
    unsigned char file_aes_key[ENCR_HMAC_KEY_LEN];
    int key_iv_len = decrypt_key_iv(
        fp,
        file_start,
        aes_key_bits,
        master_key,
        hmac,
        file_aes_iv,
        file_aes_key,
        file_hmac_key
    );
    
    // read item header & update item
    read_item_header_ret ret = read_item_header(
        fp,
        file_start,
        key_iv_len,
        file_aes_key,
        file_aes_iv,
        item
    );
    
    
    // start decrypt & decompress file content, then write them to out_fp
    // decompress part is referenced from:
    // https://www.zlib.net/zpipe.c
    
    
    // jump to file_content_start
    uint64_t file_decrypt_start = item->file_start_location + key_iv_len;
    fseek(fp, (long)file_decrypt_start, SEEK_SET);
    
    
    // setup z_stream & allocate inflate state
    int zlib_ret;
    unsigned have;
    z_stream strm;
    
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    zlib_ret = inflateInit2(&strm, 15);
    condition_check(
        (zlib_ret != Z_OK),
        "Failed to init zlib inflate\n"
    );
    
    
    // setup AES cipher
    // we MUST decrypt data chunks in this way instead of using CE_AES_decrypt(),
    // otherwise we will receive wrong data in front of each chunk during incremental decryption
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, NO_PADDING);
    condition_check(
        (0 == EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, file_aes_key, file_aes_iv)),
        "Failed to init AES cipher"
    );
    int aes_chunk_len = 0, aes_output_len = 0;
    
    
    // other setup
    
    // we only use 2 buffers for this whole process to save function stack size
    // decryption steps:
    // 1. file read:        fp -> left_buff
    // 2. aes decrypt:      left_buff -> right_buff
    // 3. zlib decompress:  right_buff -> left_buff
    // 4. file write:       left_buff -> out_fp
    // 
    // allocate bigger space for decompression
    unsigned char left_buff[ZLIB_CHUNK];
    unsigned char right_buff[ZLIB_CHUNK];
    
    int file_content_padding_len = 16 - (file_size % 16);
    uint32_t header_size_ttl = ret.header_size + 4 + 4;
    
    // decrypt cursors are mapped to real byte position inside input file
    uint64_t decrypt_start = file_decrypt_start;
    uint64_t decrypt_end = decrypt_start + header_size_ttl + file_size + file_content_padding_len;
    uint64_t decrypt_cursor = decrypt_start;
    
    // decompress cursors are RELATIVE to decrypt cursors
    // they are indexes inside right_buff during zlib decompress step
    uint64_t decompress_cursor = header_size_ttl; // skip header part in first round
    uint64_t decompress_cursor_end = ZLIB_CHUNK;
    
    uint64_t size_in = 0;
    uint64_t size_out = 0;
    uint64_t size_to_read = ZLIB_CHUNK;
    
    
    // loop until inflate finishes or decryption cursor excess
    while (zlib_ret != Z_STREAM_END && decrypt_cursor < decrypt_end){
        
        // read from file & decrypt
        fread(left_buff, (size_t)1, (size_t)size_to_read, fp);
        
        condition_check(
            (0 == EVP_DecryptUpdate(ctx, right_buff, &aes_chunk_len, left_buff, (int)size_to_read)),
            "Failed to decrypt"
        );
        aes_output_len += aes_chunk_len;
        
        condition_check(
            (0 == EVP_DecryptFinal_ex(ctx, right_buff + aes_chunk_len, &aes_chunk_len)),
            "Failed to decrypt"
        );
        aes_output_len += aes_chunk_len;
        
        
        // setup zlib input buffer & size
        strm.avail_in = (uInt)(decompress_cursor_end - decompress_cursor);
        if (strm.avail_in == 0)
            break;
        strm.next_in = right_buff + decompress_cursor;
        size_in += strm.avail_in;
        
        
        // run inflate() on input until output buffer not full
        do {
            strm.avail_out = ZLIB_CHUNK;
            strm.next_out = left_buff;
            zlib_ret = inflate(&strm, Z_NO_FLUSH);
            condition_check(
                (zlib_ret == Z_STREAM_ERROR),
                "state not clobbered\n"
            );
            
            // status check after inflate
            switch (zlib_ret) {
            case Z_NEED_DICT:
                zlib_ret = Z_DATA_ERROR; //and fall through
            case Z_DATA_ERROR:
                (void)inflateEnd(&strm);
                print_exit("Z_DATA_ERROR: %s\n", strm.msg);
                break;
            case Z_MEM_ERROR:
                (void)inflateEnd(&strm);
                print_exit("Z_MEM_ERROR: %s\n", strm.msg);
                break;
            }
            // write to out_fp
            have = ZLIB_CHUNK - strm.avail_out;
            if (fwrite(left_buff, 1, have, out_fp) != have || ferror(out_fp)) {
                (void)inflateEnd(&strm);
                print_exit("Failed to write to out_fp\n");
            }
            size_out += have;
        } while (strm.avail_out == 0);
        
        
        // update cursors
        decrypt_cursor += size_to_read;
        size_to_read = ZLIB_CHUNK;
        decompress_cursor = 0;
        decompress_cursor_end = ZLIB_CHUNK;
        if (decrypt_cursor + size_to_read >= decrypt_end) { // next round is last round
            size_to_read = decrypt_end - decrypt_cursor;
            decompress_cursor_end = size_to_read;
        }
    }
    
    // cleanup
    EVP_CIPHER_CTX_free(ctx);
    (void)inflateEnd(&strm);
}

EXPORT_SYMBOL void CEArchiveItem_clean(CEArchiveItem* item)
{
    free(item->file_path);
    item->file_path = NULL;
}


int decrypt_key_iv(
    FILE* fp,
    uint64_t start,
    uint8_t aes_key_bits,
    const unsigned char* master_key,
    bool hmac,
    unsigned char* out_aes_iv,
    unsigned char* out_aes_key,
    unsigned char* out_hmac_key
)
{
    int key_size = key_size_in_bytes(aes_key_bits);
    int key_iv_len = ENCR_BLOCK_SIZE + key_size;
    if (key_size == 24)
        key_iv_len = 48;
    if (hmac)
        key_iv_len = key_iv_len + ENCR_HMAC_KEY_LEN;
    
    unsigned char* key_iv_bytes_encrypted = malloc(key_iv_len);
    unsigned char* key_iv_bytes_decrypted = malloc(key_iv_len);
    
    read_file(fp, key_iv_len, key_iv_bytes_encrypted);
    CE_AES_decrypt(key_iv_bytes_encrypted, key_iv_bytes_decrypted, key_iv_len, master_key, NULL, NO_PADDING);
    
    if (hmac) {
        read_bytes(key_iv_bytes_decrypted, ENCR_HMAC_KEY_LEN, out_hmac_key);
        read_bytes(key_iv_bytes_decrypted+ENCR_HMAC_KEY_LEN, ENCR_BLOCK_SIZE, out_aes_iv);
        read_bytes(key_iv_bytes_decrypted+ENCR_HMAC_KEY_LEN+ENCR_BLOCK_SIZE, key_size, out_aes_key);
    }
    else {
        read_bytes(key_iv_bytes_decrypted+ENCR_HMAC_KEY_LEN, ENCR_BLOCK_SIZE, out_aes_iv);
        read_bytes(key_iv_bytes_decrypted+ENCR_HMAC_KEY_LEN+ENCR_BLOCK_SIZE, key_size, out_aes_key);
    }
    
    free(key_iv_bytes_encrypted);
    free(key_iv_bytes_decrypted);
    
    return key_iv_len;
}

read_item_header_ret read_item_header(
    FILE* fp,
    uint64_t start,
    int key_iv_len,
    const unsigned char* aes_key,
    const unsigned char* aes_iv,
    CEArchiveItem* item_out
)
{
    uint32_t header = 0;
    
    // read first 16 bytes to get encrypted file header size
    unsigned char first_16_bytes_encrypted[16];
    unsigned char first_16_bytes_decrypted[16];
    read_file(fp, 16, first_16_bytes_encrypted);
    CE_AES_decrypt(first_16_bytes_encrypted, first_16_bytes_decrypted, 16, aes_key, aes_iv, NO_PADDING);
    
    header = b_read_uint32(first_16_bytes_decrypted);
    condition_check(
        (header != ENHeaderDirectory && header != ENHeaderLocalFile),
        "Invalid ArchiveItem header"
    );
    uint32_t header_size = b_read_uint32(first_16_bytes_decrypted+4);
    uint16_t header_padding_len = 0;
    
    // decrypt entire file header
    uint64_t item_header_start = start+key_iv_len;
    int item_header_size = 4+4+header_size;
    fseek(fp, (long)item_header_start, SEEK_SET);
    unsigned char* item_header_encrypted = malloc(item_header_size);
    unsigned char* item_header_decrypted = malloc(item_header_size);
    read_file(fp, item_header_size, item_header_encrypted);
    CE_AES_decrypt(item_header_encrypted, item_header_decrypted, item_header_size, aes_key, aes_iv, NO_PADDING);
    
    // read individual file header attributes
    unsigned char* end_of_header = item_header_decrypted + item_header_size;
    unsigned char* cursor = item_header_decrypted + 4 + 4;
    uint16_t path_length;
    while (cursor < end_of_header) {
        header = b_read_uint32(cursor);
        cursor += 4;
        switch (header)
        {
        case ENHeaderElementFileType:
            item_out->file_type = b_read_uint8(cursor);
            cursor += 1;
            break;
        case ENHeaderElementFileFlags:
            item_out->file_flags = b_read_uint32(cursor);
            cursor += 4;
            break;
        case ENHeaderElementFileSize:
            item_out->file_size = b_read_uint64(cursor);
            cursor += 8;
            break;
        case ENHeaderElementFilePerm:
            item_out->file_permission = b_read_uint16(cursor);
            cursor += 2;
            break;
        case ENHeaderElementFileOwner:
            item_out->file_owner = b_read_uint16(cursor);
            cursor += 2;
            break;
        case ENHeaderElementFileGroup:
            item_out->file_group = b_read_uint16(cursor);
            cursor += 2;
            break;
        case ENHeaderElementFileMDat:
            item_out->file_modification_time = b_read_uint64(cursor);
            cursor += 8;
            break;
        case ENHeaderElementFileCDat:
            item_out->file_creation_time = b_read_uint64(cursor);
            cursor += 8;
            break;
        case ENHeaderElementFilePath:
            path_length = b_read_uint16(cursor);
            cursor += 2;
            item_out->file_path_length = path_length;
            item_out->file_path = malloc(item_out->file_path_length+1);
            read_bytes(cursor, item_out->file_path_length, item_out->file_path);
            cursor += path_length;
            break;
        case ENHeaderElementFileLocator:
            item_out->file_start_location = b_read_uint64(cursor);
            cursor += 8;
            break;
        case ENHeaderElementFileHMAC:
            read_bytes(cursor, ENCR_HMAC_LEN, item_out->file_hmac);
            cursor += ENCR_HMAC_LEN;
            break;
        case ENHeaderElementFileCSize:
            item_out->file_compressed_size = b_read_uint64(cursor);
            cursor += 8;
            break;
        case ENHeaderElementPadding:
            header_padding_len = b_read_uint16(cursor);
            // reaches file header padding, force loop to end
            cursor += 2 + header_padding_len;
            end_of_header = cursor;
            break;
        }
    }
    
    read_item_header_ret ret = {
        header_size,
        header_padding_len
    };
    return ret;
}

