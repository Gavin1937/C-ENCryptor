#ifndef ARCHIVE_H
#define ARCHIVE_H

#include "macros.h"
#include "locator.h"
#include "archive_item.h"

#include <stdio.h>
#include <stdint.h>


EXPORT_SYMBOL typedef struct CEArchive {
    FILE* fp;
    int32_t size;
    CEHeaderLocator header_locator;
    CEArchiveItem archive_item; // this should be a list of items
} CEArchive;

EXPORT_SYMBOL void CEArchive_init(
    const char* file_path,
    const char* password, const uint32_t password_size,
    CEArchive* archive
);

EXPORT_SYMBOL void CEArchive_clean(CEArchive* archive);

#endif