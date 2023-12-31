
#include "../include/C-ENCryptor/locator.h"
#include "../include/C-ENCryptor/util.h"
#include "../include/C-ENCryptor/constants.h"
#include "../include/C-ENCryptor/error_handle.h"

#include <string.h>


EXPORT_SYMBOL void CEDirectoryLocator_init(
    FILE* fp,
    const uint32_t start, const uint32_t size,
    CEDirectoryLocator* locator
)
{
    if (ferror(fp)) {
        fprintf(stderr, "Failed to open file.\n");
        exit(-1);
    }
    
    fseek(fp, (long)start, SEEK_SET);
    uint32_t header = 0;
    
    // set locator info
    header = f_read_uint32(fp);
    condition_check(
        (ENHeaderElementDirLocator != header),
        "Invalid directory locator header.\n"
    );
    locator->locator_start = start;
    locator->locator_size = size;
    locator->header = header;
    
    // directory locator position, size, reserved_1, reserved_2
    locator->encrypted_position = f_read_uint64(fp);
    locator->encrypted_size = f_read_uint64(fp);
    locator->encrypted_reserved_1 = f_read_uint64(fp);
    locator->encrypted_reserved_2 = f_read_uint64(fp);
    
    // directory locator flag
    header = f_read_uint32(fp);
    condition_check(
        (ENHeaderElementDirFlags != header),
        "Invalid directory locator flag"
    );
    locator->flags = f_read_uint32(fp);
    
    // directory hmac
    if (locator->flags & ENFlagHmacDirectory) {
        header = f_read_uint32(fp);
        condition_check(
            (ENHeaderElementDirHMAC != header),
            "Invalid directory hmac header"
        );
        locator->has_directory_hmac = true;
        condition_check(
            (ENCR_HMAC_LEN != read_file(fp, ENCR_HMAC_LEN, locator->directory_hmac)),
            "Reaches EOF while reading directory_hmac.\n"
        );
    }
    else {
        locator->has_directory_hmac = false;
    }
    
    // master key & salt
    if (locator->flags & (ENFlagEncryptFiles | ENFlagEncryptDirectory)) {
        locator->has_master_salt = true;
        header = f_read_uint32(fp);
        condition_check(
            (ENHeaderElementMasterSalt != header),
            "Invalid master salt header"
        );
        condition_check(
            (ENCR_SALT_LENGTH != read_file(fp, ENCR_SALT_LENGTH, (unsigned char*)&(locator->master_salt))),
            "Reaches EOF while reading master_salt.\n"
        );
    }
    else {
        locator->has_master_salt = false;
    }
    
    // archive preview image
    header = f_read_uint32(fp);
    if (header == ENHeaderElementArchivePreview) {
        locator->has_archive_preview = true;
        locator->archive_preview_size = f_read_uint32(fp);
        locator->archive_preview_start = ftell(fp);
        fseek(fp, locator->archive_preview_size, SEEK_CUR);
    }
    else {
        locator->has_archive_preview = false;
    }
    
    // password hint
    header = f_read_uint32(fp);
    if (header == ENHeaderElementPasswordHint) {
        locator->has_password_hint = true;
        locator->password_hint_length = f_read_uint16(fp);
        locator->password_hint_start = ftell(fp);
    }
    else {
        locator->has_password_hint = false;
    }
}

EXPORT_SYMBOL int CEDirectoryLocator_decrypt_preview(
    CEDirectoryLocator* locator,
    unsigned char* master_key,
    FILE* fp,
    unsigned char* data_out
)
{
    fseek(fp, locator->archive_preview_start, SEEK_SET);
    
    unsigned char* buff = malloc(locator->archive_preview_size);
    int size_read = read_file(fp, locator->archive_preview_size, buff);
    CE_AES_decrypt(buff, data_out, locator->archive_preview_size, master_key, NULL, NO_PADDING);
    free(buff);
    
    uint8_t preview_padding = b_read_uint8(data_out + size_read - 1);
    condition_check(
        (preview_padding > ENCR_BLOCK_SIZE),
        "Invalid preview_padding, preview decryption failed\n"
    );
    size_read -= preview_padding;
    
    return size_read;
}

EXPORT_SYMBOL void CEDirectoryLocator_clean(CEDirectoryLocator* locator)
{
}


EXPORT_SYMBOL void CEHeaderLocator_init(
    FILE* fp,
    const uint32_t start, const uint32_t size,
    const char* password, const uint32_t password_size,
    CEHeaderLocator* locator
)
{
    if (ferror(fp)) {
        fprintf(stderr, "Failed to open file.\n");
        exit(-1);
    }
    
    fseek(fp, (long)start, SEEK_SET);
    uint32_t header = 0;
    
    // set locator info
    header = f_read_uint32(fp);
    condition_check(
        (ENHeaderLocator != header),
        "Invalid header locator header.\n"
    );
    locator->locator_start = start;
    locator->locator_size = size;
    locator->header = header;
    
    header = f_read_uint32(fp);
    condition_check(
        (ENHeaderElementDirLocatorVer != header),
        "Invalid header locator version"
    );
    locator->version = f_read_uint32(fp);
    uint32_t current_relative_pos = ftell(fp) - locator->locator_start;
    uint32_t dir_locator_start = locator->locator_start + current_relative_pos;
    uint32_t dir_locator_size = locator->locator_size - current_relative_pos;
    CEDirectoryLocator_init(fp, dir_locator_start, dir_locator_size, &(locator->directory_locator));
    
    // version check
    condition_check(
        (locator->version > 0x00000100),
        "ENEncryptedArchiveUnsupportedVersion"
    );
    
    // evaluating state
    locator->encrypt_files = (locator->directory_locator.flags & ENFlagEncryptFiles) != 0;
    locator->encrypt_directory = (locator->directory_locator.flags & ENFlagEncryptDirectory) != 0;
    locator->compress_files = (locator->directory_locator.flags & ENFlagCompressFiles) != 0;
    locator->calculate_files_hmac = (locator->directory_locator.flags & ENFlagHmacFiles) != 0;
    locator->calculate_directory_hmac = (locator->directory_locator.flags & ENFlagHmacDirectory) != 0;
    
    // determine aes_key_bits
    uint8_t alg = (locator->directory_locator.flags >> 8) & 0xff;
    if (alg == ENFlagAES128)
        locator->aes_key_bits = (uint8_t)128;
    else if (alg == ENFlagAES192)
        locator->aes_key_bits = (uint8_t)192;
    else if (alg == ENFlagAES256)
        locator->aes_key_bits = (uint8_t)256;
    else {
        condition_check(
            true, "ENEncryptedArchiveInvalidEncryptionSettings"
        );
    }
    
    // get master key from password
    derive_master_key(
        locator->master_key,
        password, password_size,
        locator->directory_locator.master_salt,
        ENCR_SALT_LENGTH,
        locator->aes_key_bits
    );
    
    // decrypt directory locator
    decrypt_locator(
        locator->master_key,
        &(locator->directory_locator.encrypted_position),
        &(locator->directory_locator.encrypted_size),
        &(locator->directory_locator.encrypted_reserved_1),
        &(locator->directory_locator.encrypted_reserved_2),
        &(locator->directory_locator.decrypted_position),
        &(locator->directory_locator.decrypted_size),
        &(locator->directory_locator.decrypted_reserved_1),
        &(locator->directory_locator.decrypted_reserved_2)
    );
}

EXPORT_SYMBOL void CEHeaderLocator_clean(CEHeaderLocator* locator)
{
    CEDirectoryLocator_clean(&(locator->directory_locator));
}
