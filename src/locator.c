
#include "../include/locator.h"
#include "../include/util.h"
#include "../include/constants.h"
#include "../include/error_handle.h"

#include <string.h>


EXPORT_FUNC void DirectoryLocator_init(
    FILE* fp,
    const uint32_t start, const uint32_t size,
    DirectoryLocator* locator
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
    locator->position = f_read_uint64(fp);
    locator->size = f_read_uint64(fp);
    locator->reserved_1 = f_read_uint64(fp);
    locator->reserved_2 = f_read_uint64(fp);
    
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
        locator->directory_hmac;
        read_file(fp, ENCR_HMAC_LEN, locator->directory_hmac);
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
        read_file(fp, ENCR_SALT_LENGTH, (unsigned char*)&(locator->master_salt));
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
        locator->password_length = f_read_uint16(fp);
        locator->password_start = ftell(fp);
    }
    else {
        locator->has_password_hint = false;
    }
}

EXPORT_FUNC void DirectoryLocator_clean(DirectoryLocator* locator)
{
    locator->locator_start = 0;
    locator->locator_size = 0;
    locator->header = 0;
    locator->position = 0;
    locator->size = 0;
    locator->reserved_1 = 0;
    locator->reserved_2 = 0;
    locator->flags = 0;
    locator->has_directory_hmac = false;
    memset(locator->directory_hmac, 0, ENCR_HMAC_LEN);
    locator->has_master_salt = false;
    memset(locator->master_salt, 0, ENCR_SALT_LENGTH);
    locator->has_archive_preview = false;
    locator->archive_preview_start = 0;
    locator->archive_preview_size = 0;
    locator->has_password_hint = false;
    locator->password_start = 0;
    locator->password_length = 0;
}


EXPORT_FUNC void HeaderLocator_init(
    FILE* fp,
    const uint32_t start, const uint32_t size,
    char* password, const uint32_t password_size,
    HeaderLocator* locator
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
    DirectoryLocator_init(fp, dir_locator_start, dir_locator_size, &(locator->directory_locator));
    
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
        locator->aes_key_bits = 128;
    else if (alg == ENFlagAES192)
        locator->aes_key_bits = 192;
    else if (alg == ENFlagAES256)
        locator->aes_key_bits = 256;
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
}

EXPORT_FUNC void HeaderLocator_clean(HeaderLocator* locator)
{
    locator->locator_start = 0;
    locator->locator_size = 0;
    locator->header = 0;
    locator->version = 0;
    DirectoryLocator_clean(&(locator->directory_locator));
    locator->encrypt_files = 0;
    locator->encrypt_directory = 0;
    locator->compress_files = 0;
    locator->calculate_files_hmac = 0;
    locator->calculate_directory_hmac = 0;
    locator->aes_key_bits = 0;
    memset(locator->master_key, 0, AES_CBC_KEY_LENGTH);
}
