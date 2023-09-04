
#include "../include/C-ENCryptor/archive_item.h"
#include "../include/C-ENCryptor/util.h"
#include "../include/C-ENCryptor/error_handle.h"
#include "../include/C-ENCryptor/crypto.h"
#include "../include/C-ENCryptor/constants.h"

#include <stdlib.h>


EXPORT_SYMBOL void CEArchiveItem_init(
    FILE* fp,
    uint64_t start,
    uint64_t size,
    uint8_t aes_key_bits,
    unsigned char* master_key,
    bool hmac,
    CEArchiveItem* item
)
{
    fseek(fp, (long)start, SEEK_SET);
    
    // reading current item's key & iv
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
        read_bytes(key_iv_bytes_decrypted, ENCR_HMAC_KEY_LEN, item->item_hmac_key);
        read_bytes(key_iv_bytes_decrypted+ENCR_HMAC_KEY_LEN, ENCR_BLOCK_SIZE, item->item_aes_iv);
        read_bytes(key_iv_bytes_decrypted+ENCR_HMAC_KEY_LEN+ENCR_BLOCK_SIZE, key_size, item->item_aes_key);
    }
    else {
        read_bytes(key_iv_bytes_decrypted+ENCR_HMAC_KEY_LEN, ENCR_BLOCK_SIZE, item->item_aes_iv);
        read_bytes(key_iv_bytes_decrypted+ENCR_HMAC_KEY_LEN+ENCR_BLOCK_SIZE, key_size, item->item_aes_key);
    }
    
    free(key_iv_bytes_encrypted);
    free(key_iv_bytes_decrypted);
    
    // read file record
    uint32_t header = 0;
    
    // read first 16 bytes to get encrypted file header size
    unsigned char first_16_bytes_encrypted[16];
    unsigned char first_16_bytes_decrypted[16];
    read_file(fp, 16, first_16_bytes_encrypted);
    CE_AES_decrypt(first_16_bytes_encrypted, first_16_bytes_decrypted, 16, item->item_aes_key, item->item_aes_iv, NO_PADDING);
    
    header = b_read_uint32(first_16_bytes_decrypted);
    condition_check(
        (header != ENHeaderDirectory),
        "Invalid ArchiveItem header"
    );
    item->header_size = b_read_uint32(first_16_bytes_decrypted+4);
    
    // decrypt entire file header
    uint64_t item_header_start = start+key_iv_len;
    int item_header_size = 4+4+item->header_size;
    fseek(fp, (long)item_header_start, SEEK_SET);
    unsigned char* item_header_encrypted = malloc(item_header_size);
    unsigned char* item_header_decrypted = malloc(item_header_size);
    read_file(fp, item_header_size, item_header_encrypted);
    CE_AES_decrypt(item_header_encrypted, item_header_decrypted, item_header_size, item->item_aes_key, item->item_aes_iv, NO_PADDING);
    
    // read individual file header attributes
    unsigned char* end_of_header = item_header_decrypted + item_header_size;
    unsigned char* cursor = item_header_decrypted + 4 + 4;
    while (cursor < end_of_header) {
        header = b_read_uint32(cursor);
        cursor += 4;
        switch (header)
        {
        case ENHeaderElementFileType:
            item->file_type = b_read_uint8(cursor);
            cursor += 1;
            break;
        case ENHeaderElementFileFlags:
            item->file_flags = b_read_uint32(cursor);
            cursor += 4;
            break;
        case ENHeaderElementFileSize:
            item->file_size = b_read_uint64(cursor);
            cursor += 8;
            break;
        case ENHeaderElementFilePerm:
            item->file_permission = b_read_uint16(cursor);
            cursor += 2;
            break;
        case ENHeaderElementFileOwner:
            item->file_owner = b_read_uint16(cursor);
            cursor += 2;
            break;
        case ENHeaderElementFileGroup:
            item->file_group = b_read_uint16(cursor);
            cursor += 2;
            break;
        case ENHeaderElementFileMDat:
            item->file_modification_time = b_read_uint64(cursor);
            cursor += 8;
            break;
        case ENHeaderElementFileCDat:
            item->file_creation_time = b_read_uint64(cursor);
            cursor += 8;
            break;
        case ENHeaderElementFilePath:
            uint16_t path_length = b_read_uint16(cursor);
            cursor += 2;
            item->file_path_length = path_length;
            item->file_path = malloc(item->file_path_length+1);
            read_bytes(cursor, item->file_path_length, item->file_path);
            cursor += path_length;
            break;
        case ENHeaderElementFileLocator:
            item->file_start_location = b_read_uint64(cursor);
            cursor += 8;
            break;
        case ENHeaderElementFileHMAC:
            read_bytes(cursor, ENCR_HMAC_LEN, item->file_hmac);
            cursor += ENCR_HMAC_LEN;
            break;
        case ENHeaderElementFileCSize:
            item->file_compressed_size = b_read_uint64(cursor);
            cursor += 8;
            break;
        case ENHeaderElementPadding:
            item->header_padding_len = b_read_uint16(cursor);
            // reaches file header padding, force loop to end
            cursor += 2 + item->header_padding_len;
            end_of_header = cursor;
            break;
        }
    }
}

EXPORT_SYMBOL void CEArchiveItem_decrypt(
    CEArchiveItem* item,
    FILE* fp,
    unsigned char* data_out
)
{
    fseek(fp, item->file_start_location, SEEK_SET);
    
    
}

EXPORT_SYMBOL void CEArchiveItem_clean(CEArchiveItem* item)
{
    free(item->file_path);
    item->file_path = NULL;
}


