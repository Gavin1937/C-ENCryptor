
#include "../include/archive.h"
#include "../include/constants.h"
#include "../include/util.h"
#include "../include/error_handle.h"
#include "../include/locator.h"
#include "../include/archive_item.h"

#include <stdlib.h>


EXPORT_SYMBOL void CEArchive_init(
    const char* file_path,
    const char* password, const uint32_t password_size,
    CEArchive* archive
)
{
    // open file in binary mode
    FILE* fp;
    fopen_s(&fp, file_path, "rb");
    uint32_t header = 0;
    
    if (ferror(fp)) {
        fprintf(stderr, "Failed to open file.\n");
        exit(-1);
    }
    
    // check archive file header & set basic archive info
    header = f_read_uint32(fp);
    condition_check(
        (ENEncryptoHeader != header),
        "Invalid archive header.\n"
    );
    archive->fp = fp;
    
    fseek(archive->fp, 0L, SEEK_END);
    archive->size = ftell(archive->fp);
    fseek(archive->fp, 0L, SEEK_SET);
    
    // init CEHeaderLocator
    
    // get CEHeaderLocator size
    fseek(archive->fp, -8L, SEEK_END);
    header = f_read_uint32(fp);
    int32_t header_locator_size = f_read_uint32(fp);
    condition_check(
        (header != ENHeaderElementDirLocatorSize || header_locator_size + 4 > archive->size),
        "Invalid directory locator size.\n"
    );
    
    CEHeaderLocator_init(
        archive->fp,
        archive->size-header_locator_size, header_locator_size,
        password, password_size,
        &(archive->header_locator)
    );
    
    // read file records / archive items
    CEArchiveItem_init(
        archive->fp,
        archive->header_locator.directory_locator.decrypted_position,
        archive->header_locator.directory_locator.decrypted_size,
        archive->header_locator.aes_key_bits,
        archive->header_locator.master_key,
        (archive->header_locator.calculate_files_hmac || archive->header_locator.calculate_directory_hmac),
        &(archive->archive_item)
    );
}

EXPORT_SYMBOL void CEArchive_clean(CEArchive* archive)
{
    if (!archive->fp)
        fclose(archive->fp);
    archive->size = 0;
    CEHeaderLocator_clean(&(archive->header_locator));
    CEArchiveItem_clean(&(archive->archive_item));
}