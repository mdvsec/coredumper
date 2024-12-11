#include "mem_reader.h"
#include <limits.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include "parser.h"

#define CHUNK_SIZE 4096

extern ssize_t data_offset;

int dump_memory_region(const int fd, const Elf64_Phdr* phdr, const pid_t pid) {
    int mem_fd;
    size_t len;
    size_t offset;
    char mem_path[32];
    char buf[CHUNK_SIZE];

    if (lseek(fd, data_offset, SEEK_SET) < 0) {
        return -1;
    }

    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        return -1;
    }

    len = phdr->p_memsz;
    offset = 0;

    memset(buf, 0, sizeof(buf));
    while (offset < len) {
        ssize_t read_sz = (len - offset) > CHUNK_SIZE ? CHUNK_SIZE : len - offset;
        ssize_t write_sz = 0;
        ssize_t write_total_sz = 0;

        if (phdr->p_flags & PF_R) {
            read_sz = pread(mem_fd,
                            buf,
                            read_sz,
                            phdr->p_vaddr + offset);

            if (read_sz < 0) {
                goto cleanup;
            }
        }

        while (write_total_sz < read_sz) {
            write_sz = write(fd,
                             buf + write_total_sz,
                             read_sz - write_total_sz);
            if (write_sz < 0) {
                goto cleanup;
            }

            write_total_sz += write_sz;
        }

        offset += read_sz;
    }

    data_offset += len;
    data_offset = (data_offset + phdr->p_align - 1) & ~(phdr->p_align - 1);

    close(mem_fd);

    return 0;

cleanup:
    close(mem_fd);
    return -1;
}
