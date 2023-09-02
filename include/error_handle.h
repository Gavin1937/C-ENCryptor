#ifndef ERROR_HANDLE_H
#define ERROR_HANDLE_H

#include <stdbool.h>

void print_exit(const char *const _Format, ...);

void condition_check(bool _Condition, char *const _Format, ...);

#endif