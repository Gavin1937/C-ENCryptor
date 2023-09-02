#ifndef ARCHIVE_H
#define ARCHIVE_H

#include "macros.h"
#include "locator.h"

#include <stdio.h>
#include <stdint.h>


EXPORT_FUNC typedef struct Archive {
    FILE* fp;
    int32_t size;
    HeaderLocator header_locator;
} Archive;

EXPORT_FUNC void Archive_init(
    const char* file_path,
    const char* password, const uint32_t password_size,
    Archive* archive
);

EXPORT_FUNC void Archive_clean(Archive* archive);

#endif