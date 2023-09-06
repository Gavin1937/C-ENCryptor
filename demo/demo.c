#include "C-ENCryptor/ceapi.h"

#include <stdio.h>
#include <string.h>


#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__) || defined(__CYGWIN__)
#define SEPARATOR '\\'
#define SEPARATOR_STR "\\"
#define PREVIEW_OUTPUT_PATH "output\\preview.png"
#define DECRYPT_OUTPUT_PATH "output\\decrypt"
#define ARCHIVE_FILEPATH "data\\encrypted\\encrypted_img01.crypto"
#else
#define SEPARATOR '/'
#define SEPARATOR_STR "/"
#define PREVIEW_OUTPUT_PATH "output/preview.png"
#define DECRYPT_OUTPUT_PATH "output/decrypt"
#define ARCHIVE_FILEPATH "data/encrypted/encrypted_img01.crypto"
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




int main(int argc, char** argv)
{
    // setup output file path
    char base_path[2048];
    char* exe_start = strrchr(argv[0], SEPARATOR);
    int exe_pos = (exe_start - argv[0]);
    memcpy_s(base_path, 2048, argv[0], exe_pos);
    base_path[exe_pos] = 0;
    char* parent_start = strrchr(base_path, SEPARATOR);
    *parent_start = 0;
    printf("%s\n", base_path);
    
    char archive_filepath[2048] = "";
    char preview_output_path[2048] = "";
    char decrypt_output_path[2048] = "";
    
    strcat_s(archive_filepath, 2048, base_path);
    strcat_s(archive_filepath, 2048, SEPARATOR_STR);
    strcat_s(archive_filepath, 2048, ARCHIVE_FILEPATH);
    printf("archive_filepath = %s\n", archive_filepath);
    
    strcat_s(preview_output_path, 2048, base_path);
    strcat_s(preview_output_path, 2048, SEPARATOR_STR);
    strcat_s(preview_output_path, 2048, PREVIEW_OUTPUT_PATH);
    printf("preview_output_path = %s\n", preview_output_path);
    
    strcat_s(decrypt_output_path, 2048, base_path);
    strcat_s(decrypt_output_path, 2048, SEPARATOR_STR);
    strcat_s(decrypt_output_path, 2048, DECRYPT_OUTPUT_PATH);
    printf("decrypt_output_path = %s\n", decrypt_output_path);
    
    
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
    FILE* preview_fp;
    fopen_s(&preview_fp, preview_output_path, "wb+");
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
    FILE* fp_out;
    fopen_s(&fp_out, decrypt_output_path, "wb");
    
    CEArchiveItem_decrypt(&arc.archive_item, arc.fp, fp_out, arc.header_locator.aes_key_bits, arc.header_locator.master_key, hmac);
    
    fclose(fp_out);
    
    printf("Finish decrypt archive_item\n");
    
    
    // cleanup
    CEArchive_clean(&arc);
    
    return 0;
}