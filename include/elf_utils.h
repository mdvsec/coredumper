#ifndef ELF_UTILS_H
#define ELF_UTILS_H

#include <stddef.h>
#include <sys/types.h>
#include "proc_parser.h"

int write_elf_header(const int, const ssize_t);
int write_elf_program_headers(const int, const maps_entry_t*, const pid_t, size_t*);

#endif // ELF_UTILS_H
