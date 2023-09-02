#ifndef LOCATOR_H
#define LOCATOR_H

#include "macros.h"
#include "constants.h"
#include "crypto.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>


EXPORT_FUNC typedef struct DirectoryLocator {
    uint32_t locator_start;
    uint32_t locator_size;
    uint32_t header;
    uint64_t position;
    uint64_t size;
    uint64_t reserved_1;
    uint64_t reserved_2;
    uint32_t flags;
    bool has_directory_hmac;
    unsigned char directory_hmac[ENCR_HMAC_LEN];
    bool has_master_salt;
    unsigned char master_salt[ENCR_SALT_LENGTH];
    bool has_archive_preview;
    uint32_t archive_preview_start;
    uint32_t archive_preview_size;
    bool has_password_hint;
    uint64_t password_start;
    uint16_t password_length;
} DirectoryLocator;

EXPORT_FUNC void DirectoryLocator_init(
    FILE* fp,
    const uint32_t start, const uint32_t size,
    DirectoryLocator* locator
);

EXPORT_FUNC void DirectoryLocator_clean(DirectoryLocator* locator);


EXPORT_FUNC typedef struct HeaderLocator {
    uint32_t locator_start;
    uint32_t locator_size;
    uint32_t header;
    uint32_t version;
    DirectoryLocator directory_locator;
    bool encrypt_files;
    bool encrypt_directory;
    bool compress_files;
    bool calculate_files_hmac;
    bool calculate_directory_hmac;
    uint8_t aes_key_bits;
    unsigned char master_key[AES_CBC_KEY_LENGTH];
} HeaderLocator;

EXPORT_FUNC void HeaderLocator_init(
    FILE* fp,
    const uint32_t start, const uint32_t size,
    char* password, const uint32_t password_size,
    HeaderLocator* locator
);

EXPORT_FUNC void HeaderLocator_clean(HeaderLocator* locator);

#endif