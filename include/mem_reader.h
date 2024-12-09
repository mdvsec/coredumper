#ifndef MEM_READER_H 
#define MEM_READER_H

#include <sys/types.h>
#include <elf.h>

int dump_memory_region(const Elf64_Phdr*, const int, const pid_t);

#endif
