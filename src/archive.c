
#include "../include/archive.h"
#include "../include/constants.h"
#include "../include/util.h"
#include "../include/error_handle.h"
#include "../include/locator.h"

#include <stdlib.h>


EXPORT_FUNC void Archive_init(
    const char* file_path,
    char* password, const uint32_t password_size,
    Archive* archive
)
{
    FILE* fp;
    fopen_s(&fp, file_path, "r");
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
    
    // init HeaderLocator
    
    // get HeaderLocator size
    fseek(archive->fp, -8L, SEEK_END);
    header = f_read_uint32(fp);
    int32_t header_locator_size = f_read_uint32(fp);
    condition_check(
        (header != ENHeaderElementDirLocatorSize || header_locator_size + 4 > archive->size),
        "Invalid directory locator size.\n"
    );
    
    HeaderLocator_init(
        archive->fp,
        archive->size-header_locator_size, header_locator_size,
        password, password_size,
        &(archive->header_locator)
    );
    
}

EXPORT_FUNC void Archive_clean(Archive* archive)
{
    if (!archive->fp)
        fclose(archive->fp);
    archive->size = 0;
    HeaderLocator_clean(&(archive->header_locator));
}