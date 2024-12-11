#ifndef MEM_READER_H 
#define MEM_READER_H

#include <sys/types.h>
#include <elf.h>

int dump_memory_region(const int, const Elf64_Phdr*, const pid_t);

#endif
