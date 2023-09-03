#ifndef ARCHIVE_ITEM_H
#define ARCHIVE_ITEM_H

#include "macros.h"
#include "constants.h"

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>


EXPORT_SYMBOL typedef struct CEArchiveItem {
    unsigned char item_aes_iv[AES_CBC_IV_LENGTH];
    unsigned char item_aes_key[AES_CBC_KEY_LENGTH];
    unsigned char item_hmac_key[ENCR_HMAC_KEY_LEN];
    uint32_t header_size;
    uint8_t file_type;
    uint32_t file_flags;
    uint64_t file_size;
    uint16_t file_permission;
    uint16_t file_owner;
    uint16_t file_group;
    uint64_t file_modification_time;
    uint64_t file_creation_time;
    unsigned char* file_path;
    uint16_t file_path_length;
    uint64_t file_start_location;
    unsigned char file_hmac[ENCR_HMAC_LEN];
    uint64_t file_compressed_size;
    uint16_t header_padding_len;
} CEArchiveItem;

EXPORT_SYMBOL void CEArchiveItem_init(
    FILE* fp,
    uint64_t start,
    uint64_t size,
    uint8_t aes_key_bits,
    unsigned char* master_key,
    bool hmac,
    CEArchiveItem* item
);

EXPORT_SYMBOL void CEArchiveItem_clean(CEArchiveItem* item);

#endif