
#include "../include/C-ENCryptor/util.h"
#include "../include/C-ENCryptor/error_handle.h"

#include <assert.h>
#include <string.h>


int read_file(FILE* fp, const int size_to_read, unsigned char* data_out)
{
    assert(fp);
    
    int size_read = (int)fread_s(data_out, size_to_read, 1, size_to_read, fp);
    condition_check(
        (ferror(fp) != 0),
        "Failed to read from file\n"
    );
    
    return size_read;
}
void read_bytes(const unsigned char* data_in, const int size_to_read, unsigned char* data_out)
{
    memcpy_s(data_out, size_to_read, data_in, size_to_read);
}


const uint8_t f_read_uint8(FILE* fp)
{
    assert(fp);
    
    unsigned char buff[1];
    fread_s(buff, 1, sizeof(unsigned char), 1, fp);
    assert(ferror(fp) == 0);
    
    return *((uint8_t*)buff);
}
const uint8_t b_read_uint8(const unsigned char* data_in)
{
    assert(data_in != NULL);
    
    return *((uint8_t*)data_in);
}


const uint16_t f_read_uint16(FILE* fp)
{
    assert(fp);
    
    unsigned char buff[2];
    fread_s(buff, 2, sizeof(unsigned char), 2, fp);
    assert(ferror(fp) == 0);
    
    return *((uint16_t*)buff);
}
const uint16_t b_read_uint16(const unsigned char* data_in)
{
    assert(data_in != NULL);
    
    return *((uint16_t*)data_in);
}


const uint32_t f_read_uint32(FILE* fp)
{
    assert(fp);
    
    unsigned char buff[4];
    fread_s(buff, 4, sizeof(unsigned char), 4, fp);
    assert(ferror(fp) == 0);
    
    return *((uint32_t*)buff);
}
const uint32_t b_read_uint32(const unsigned char* data_in)
{
    assert(data_in != NULL);
    
    return *((uint32_t*)data_in);
}


const uint64_t f_read_uint64(FILE* fp)
{
    assert(fp);
    
    unsigned char buff[8];
    fread_s(buff, 8, sizeof(unsigned char), 8, fp);
    assert(ferror(fp) == 0);
    
    return *((uint64_t*)buff);
}
const uint64_t b_read_uint64(const unsigned char* data_in)
{
    assert(data_in != NULL);
    
    return *((uint64_t*)data_in);
}


