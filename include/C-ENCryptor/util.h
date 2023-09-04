#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdint.h>

int read_file(FILE* fp, const int size_to_read, unsigned char* data_out);
void read_bytes(const unsigned char* data_in, const int size_to_read, unsigned char* data_out);

const uint8_t f_read_uint8(FILE* fp);
const uint8_t b_read_uint8(const unsigned char* data_in);

const uint16_t f_read_uint16(FILE* fp);
const uint16_t b_read_uint16(const unsigned char* data_in);

const uint32_t f_read_uint32(FILE* fp);
const uint32_t b_read_uint32(const unsigned char* data_in);

const uint64_t f_read_uint64(FILE* fp);
const uint64_t b_read_uint64(const unsigned char* data_in);

#endif