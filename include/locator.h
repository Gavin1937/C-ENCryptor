#ifndef LOCATOR_H
#define LOCATOR_H

#include "macros.h"
#include "constants.h"
#include "crypto.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>


EXPORT_SYMBOL typedef struct CEDirectoryLocator {
    uint32_t locator_start;
    uint32_t locator_size;
    uint32_t header;
    uint64_t encrypted_position;
    uint64_t encrypted_size;
    uint64_t encrypted_reserved_1;
    uint64_t encrypted_reserved_2;
    uint32_t flags;
    bool has_directory_hmac;
    unsigned char directory_hmac[ENCR_HMAC_LEN];
    bool has_master_salt;
    unsigned char master_salt[ENCR_SALT_LENGTH];
    bool has_archive_preview;
    uint32_t archive_preview_start;
    uint32_t archive_preview_size;
    bool has_password_hint;
    uint64_t password_hint_start;
    uint16_t password_hint_length;
    uint64_t decrypted_position;
    uint64_t decrypted_size;
    uint64_t decrypted_reserved_1;
    uint64_t decrypted_reserved_2;
} CEDirectoryLocator;

EXPORT_SYMBOL void CEDirectoryLocator_init(
    FILE* fp,
    const uint32_t start, const uint32_t size,
    CEDirectoryLocator* locator
);

EXPORT_SYMBOL int CEDirectoryLocator_decrypt_preview(
    CEDirectoryLocator* locator,
    unsigned char* master_key,
    FILE* fp,
    unsigned char* data_out
);

EXPORT_SYMBOL void CEDirectoryLocator_clean(CEDirectoryLocator* locator);


EXPORT_SYMBOL typedef struct CEHeaderLocator {
    uint32_t locator_start;
    uint32_t locator_size;
    uint32_t header;
    uint32_t version;
    CEDirectoryLocator directory_locator;
    bool encrypt_files;
    bool encrypt_directory;
    bool compress_files;
    bool calculate_files_hmac;
    bool calculate_directory_hmac;
    uint8_t aes_key_bits;
    unsigned char master_key[AES_CBC_KEY_LENGTH];
} CEHeaderLocator;

EXPORT_SYMBOL void CEHeaderLocator_init(
    FILE* fp,
    const uint32_t start, const uint32_t size,
    const char* password, const uint32_t password_size,
    CEHeaderLocator* locator
);

EXPORT_SYMBOL void CEHeaderLocator_clean(CEHeaderLocator* locator);

#endif