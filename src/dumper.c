#include "dumper.h"
#include <limits.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define CHUNK_SIZE 4096
#define DUMP_SUCCESS 0
#define DUMP_ERROR -1

static int is_readable(const maps_entry_t* entry) {
    return entry->perms[0] == 'r' && strcmp(entry->pathname, "[vvar]");
}

int dump_procfs_mem(pid_t pid, maps_entry_t* pid_maps) {
    char mem_path[32];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        fprintf(stderr,
                "Error occured while opening file /proc/%d/mem\n",
                pid);
        return DUMP_ERROR;
    }

    maps_entry_t* curr = pid_maps;
    while (curr) {
        char region_name[256];
        snprintf(region_name, sizeof(region_name), "0x%lx-0x%lx", 
                 curr->start_addr, curr->end_addr);

        printf("[DEBUG] Attempt to read %s\n", region_name);

        if (!is_readable(curr)) {
            printf("[DEBUG] Skipping non-readable memory region %s\n", region_name);
            curr = curr->next;
            continue;
        }

        int region_fd = open(region_name, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
        if (region_fd < 0) {
            fprintf(stderr, 
                    "Error occured while creating a dump file %s\n", 
                    region_name);
            perror("open");
            close(mem_fd);
            return DUMP_ERROR;
        }

        size_t len = curr->end_addr - curr->start_addr;
        size_t offset = 0;
        char buf[CHUNK_SIZE];

        while (offset < len) {
            ssize_t read_sz = (len - offset) > CHUNK_SIZE ? CHUNK_SIZE : len - offset;

            read_sz = pread(mem_fd, buf, read_sz, curr->start_addr + offset);
            if (read_sz < 0) {
                fprintf(stderr,
                        "Error occured while reading file /proc/%d/mem\n", 
                        pid);
                perror("pread");
                close(region_fd);
                break;
            }

            // TBD: Incomplete write() should be handled
            ssize_t write_sz = write(region_fd, buf, read_sz);
            if (write_sz < 0) {
                fprintf(stderr,
                        "Error occured while writing to file %s\n",
                        region_name);
                close(region_fd);
                break;
            }

            offset += read_sz;
        }

        close(region_fd);

        curr = curr->next;
    }

    close(mem_fd);

    return DUMP_SUCCESS;
}
