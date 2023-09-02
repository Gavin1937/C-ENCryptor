
#include "../include/error_handle.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>


void print_exit(const char *const _Format, ...)
{
    va_list _ArgList;
    va_start(_ArgList, _Format);
    vfprintf(stderr, _Format, _ArgList);
    va_end(_ArgList);
    exit(-1);
}

void condition_check(bool _Condition, char *const _Format, ...)
{
    if (_Condition) {
        va_list _ArgList;
        va_start(_ArgList, _Format);
        vfprintf(stderr, _Format, _ArgList);
        va_end(_ArgList);
        exit(-1);
    }
}
