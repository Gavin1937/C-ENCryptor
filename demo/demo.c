#include "C-ENCryptor/ceapi.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>


#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__) || defined(__CYGWIN__)
#define SEPARATOR '\\'
#define SEPARATOR_STR "\\"
#define PREVIEW_OUTPUT_FILENAME "preview.png"
#define DECRYPT_OUTPUT_FILENAME "decrypt"
#else
#define SEPARATOR '/'
#define SEPARATOR_STR "/"
#define PREVIEW_OUTPUT_FILENAME "preview.png"
#define DECRYPT_OUTPUT_FILENAME "decrypt"
#endif



void print_string(const char* data, const int size, const char* text_in_front, bool with_space)
{
    printf(text_in_front);
    for (int i = 0; i < size; ++i) {
        if (with_space) printf("%c ", data[i]);
        else printf("%c", data[i]);
    }
    printf("\n");
}

void print_bytes(const unsigned char* data, const int size, const char* text_in_front, bool with_space)
{
    printf(text_in_front);
    for (int i = 0; i < size; ++i) {
        if (with_space) printf("%02x ", data[i]);
        else printf("%02x", data[i]);
    }
    printf("\n");
}

/* By liw. */
// https://stackoverflow.com/a/1643946
static char *last_strstr(const char *haystack, const char *needle)
{
    if (*needle == '\0')
        return (char *) haystack;
    
    char *result = NULL;
    for (;;) {
        char *p = strstr(haystack, needle);
        if (p == NULL)
            break;
        result = p;
        haystack = p + 1;
    }
    
    return result;
}



int main(int argc, char** argv)
{
    if (argc <= 1) {
        printf("Usage: demo [archive_filepath] [output_folderpath]\n");
        exit(0);
    }
    
    // setup output file path
    char* archive_filepath = argv[1];
    char preview_output_filename[2048] = "";
    char decrypt_output_filename[2048] = "";
    
    printf("archive_filepath = %s\n", archive_filepath);
    
    bool need_separator = (argv[2][strlen(argv[2])-1] != SEPARATOR);
    strcat(preview_output_filename, argv[2]);
    if (need_separator)
        strcat(preview_output_filename, SEPARATOR_STR);
    strcat(preview_output_filename, PREVIEW_OUTPUT_FILENAME);
    printf("preview_output_filename = %s\n", preview_output_filename);
    
    strcat(decrypt_output_filename, argv[2]);
    if (need_separator)
        strcat(decrypt_output_filename, SEPARATOR_STR);
    strcat(decrypt_output_filename, DECRYPT_OUTPUT_FILENAME);
    printf("decrypt_output_filename = %s\n", decrypt_output_filename);
    
    
    // setup CEArchive
    CEArchive arc;
    CEArchive_init(
        archive_filepath,
        "1234", 4,
        &arc
    );
    
    // printing data inside CEArchive
    printf("arc.size = %ld\n", arc.size);
    
    printf("arc.header_locator.locator_start = %ld\n", arc.header_locator.locator_start);
    printf("arc.header_locator.locator_size = %ld\n", arc.header_locator.locator_size);
    printf("arc.header_locator.header = %d\n", arc.header_locator.header);
    printf("arc.header_locator.version = %d\n", arc.header_locator.version);
    
    printf("arc.header_locator.directory_locator.locator_start = %d\n", arc.header_locator.directory_locator.locator_start);
    printf("arc.header_locator.directory_locator.locator_size = %d\n", arc.header_locator.directory_locator.locator_size);
    printf("arc.header_locator.directory_locator.header = %d\n", arc.header_locator.directory_locator.header);
    printf("arc.header_locator.directory_locator.position = %lld\n", arc.header_locator.directory_locator.encrypted_position);
    printf("arc.header_locator.directory_locator.size = %lld\n", arc.header_locator.directory_locator.encrypted_size);
    printf("arc.header_locator.directory_locator.reserved_1 = %lld\n", arc.header_locator.directory_locator.encrypted_reserved_1);
    printf("arc.header_locator.directory_locator.reserved_2 = %lld\n", arc.header_locator.directory_locator.encrypted_reserved_2);
    printf("arc.header_locator.directory_locator.flags = %d\n", arc.header_locator.directory_locator.flags);
    printf("arc.header_locator.directory_locator.has_directory_hmac = %d\n", arc.header_locator.directory_locator.has_directory_hmac);
    if (arc.header_locator.directory_locator.has_directory_hmac)
        print_bytes(arc.header_locator.directory_locator.directory_hmac, 32, "arc.header_locator.directory_locator.directory_hmac = ", true);
    printf("arc.header_locator.directory_locator.has_master_salt = %d\n", arc.header_locator.directory_locator.has_master_salt);
    if (arc.header_locator.directory_locator.has_master_salt)
        print_bytes(arc.header_locator.directory_locator.master_salt, 16, "arc.header_locator.directory_locator.master_salt = ", true);
    printf("arc.header_locator.directory_locator.has_archive_preview = %d\n", arc.header_locator.directory_locator.has_archive_preview);
    printf("arc.header_locator.directory_locator.archive_preview_start = %d\n", arc.header_locator.directory_locator.archive_preview_start);
    printf("arc.header_locator.directory_locator.archive_preview_size = %d\n", arc.header_locator.directory_locator.archive_preview_size);
    printf("arc.header_locator.directory_locator.has_password_hint = %d\n", arc.header_locator.directory_locator.has_password_hint);
    printf("arc.header_locator.directory_locator.password_hint_start = %lld\n", arc.header_locator.directory_locator.password_hint_start);
    printf("arc.header_locator.directory_locator.password_hint_length = %d\n", arc.header_locator.directory_locator.password_hint_length);
    
    printf("arc.header_locator.encrypt_files = %d\n", arc.header_locator.encrypt_files);
    printf("arc.header_locator.encrypt_directory = %d\n", arc.header_locator.encrypt_directory);
    printf("arc.header_locator.compress_files = %d\n", arc.header_locator.compress_files);
    printf("arc.header_locator.calculate_files_hmac = %d\n", arc.header_locator.calculate_files_hmac);
    printf("arc.header_locator.calculate_directory_hmac = %d\n", arc.header_locator.calculate_directory_hmac);
    printf("arc.header_locator.aes_key_bits = %d\n", arc.header_locator.aes_key_bits);
    print_bytes(arc.header_locator.master_key, AES_CBC_KEY_LENGTH, "arc.header_locator.master_key = ", true);
    
    printf("arc.header_locator.directory_locator.decrypted_position = %I64d\n", arc.header_locator.directory_locator.decrypted_position);
    printf("arc.header_locator.directory_locator.decrypted_size = %I64d\n", arc.header_locator.directory_locator.decrypted_size);
    printf("arc.header_locator.directory_locator.decrypted_reserved_1 = %I64d\n", arc.header_locator.directory_locator.decrypted_reserved_1);
    printf("arc.header_locator.directory_locator.decrypted_reserved_2 = %I64d\n", arc.header_locator.directory_locator.decrypted_reserved_2);
    
    // decrypt preview image
    unsigned char* preview_bytes = malloc(arc.header_locator.directory_locator.archive_preview_size);
    int size_read = CEDirectoryLocator_decrypt_preview(&(arc.header_locator.directory_locator), arc.header_locator.master_key, arc.fp, preview_bytes);
    FILE* preview_fp = fopen(preview_output_filename, "wb+");
    if (preview_fp && preview_bytes) {
        fwrite(preview_bytes, 1, size_read, preview_fp);
        fclose(preview_fp);
    }
    free(preview_bytes);
    
    
    print_bytes(arc.archive_item.item_aes_iv, AES_CBC_IV_LENGTH, "arc.archive_item.item_aes_iv = ", true);
    print_bytes(arc.archive_item.item_aes_key, AES_CBC_KEY_LENGTH, "arc.archive_item.item_aes_key = ", true);
    bool hmac = (arc.header_locator.calculate_files_hmac || arc.header_locator.calculate_directory_hmac);
    if (hmac)
        print_bytes(arc.archive_item.item_hmac_key, ENCR_HMAC_KEY_LEN, "arc.archive_item.item_hmac_key = ", true);
    
    printf("arc.archive_item.header_size = %I32d\n", arc.archive_item.header_size);
    printf("arc.archive_item.file_type = %d\n", arc.archive_item.file_type);
    printf("arc.archive_item.file_flags = %I32d\n", arc.archive_item.file_flags);
    printf("arc.archive_item.file_size = %I64d\n", arc.archive_item.file_size);
    printf("arc.archive_item.file_permission = %d\n", arc.archive_item.file_permission);
    printf("arc.archive_item.file_owner = %d\n", arc.archive_item.file_owner);
    printf("arc.archive_item.file_group = %d\n", arc.archive_item.file_group);
    printf("arc.archive_item.file_modification_time = %I64d\n", arc.archive_item.file_modification_time);
    printf("arc.archive_item.file_creation_time = %I64d\n", arc.archive_item.file_creation_time);
    print_string(arc.archive_item.file_path, arc.archive_item.file_path_length, "arc.archive_item.file_path = ", false);
    printf("arc.archive_item.file_start_location = %I64d\n", arc.archive_item.file_start_location);
    print_bytes(arc.archive_item.file_hmac, ENCR_HMAC_LEN, "arc.archive_item.file_hmac = ", true);
    printf("arc.archive_item.file_compressed_size = %I64d\n", arc.archive_item.file_compressed_size);
    printf("arc.archive_item.header_padding_len = %d\n", arc.archive_item.header_padding_len);
    
    
    // decrypt output file
    FILE* fp_out = fopen(decrypt_output_filename, "wb");
    
    CEArchiveItem_decrypt(&arc.archive_item, arc.fp, fp_out, arc.header_locator.aes_key_bits, arc.header_locator.master_key, hmac);
    
    fclose(fp_out);
    
    printf("Finish decrypt archive_item\n");
    
    
    // cleanup
    CEArchive_clean(&arc);
    
    return 0;
}