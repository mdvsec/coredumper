#ifndef ELFUTILS_H
#define ELFUTILS_H

#include <stddef.h>
#include "parser.h"

int write_elf_header(const int, const size_t);
int write_program_header_table(const int, const maps_entry_t*);

#endif
