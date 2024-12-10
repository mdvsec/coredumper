#ifndef ELF_UTILS_H
#define ELF_UTILS_H

#include <stddef.h>
#include "parser.h"

int write_elf_header(const int);
int write_elf_program_headers(const int, const maps_entry_t*, const pid_t);

#endif
