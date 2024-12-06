#include "dumper.h"
#include <limits.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "parser.h"
#include "elf_utils.h"

#define CHUNK_SIZE 4096
#define DUMP_SUCCESS 0
#define DUMP_ERROR -1

int create_coredump(const pid_t pid) {
    int ret;
    maps_entry_t* pid_maps;

    pid_maps = parse_procfs_maps(pid);
    if (!pid_maps) {
        fprintf(stderr,
                "Error occured while parsing /proc/%d/maps\n",
                pid);
        return -1;
    }

    print_maps_list(pid_maps);

    size_t phdr_count = count_proc_maps(pid_maps);
    printf("[DEBUG] Prog headers: %zu\n", phdr_count);

    char coredump_path[32];
    snprintf(coredump_path, sizeof(coredump_path), "%d_coredump", pid);

    int coredump_fd = open(coredump_path, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0600);
    if (coredump_fd < 0) {
        fprintf(stderr,
                "Error occured while creating file %s\n",
                coredump_path);
        free_maps_list(pid_maps);
        return -1;
    }

    ret = write_elf_header(coredump_fd, phdr_count);
    if (ret < 0) {
        fprintf(stderr,
                "Error occured while writing to file %s\n",
                coredump_path);
        free_maps_list(pid_maps);
        close(coredump_fd);
        return -1;
    }

    ret = write_program_header_table(coredump_fd, pid_maps, phdr_count);
    if (ret < 0) {
        fprintf(stderr,
                "Error occured while writing to file %s\n",
                coredump_path);
        free_maps_list(pid_maps);
        close(coredump_fd);
        return -1;
    }

    close(coredump_fd);

    free_maps_list(pid_maps);

    return 0;
}

static int is_readable(const maps_entry_t* entry) {
    return entry->perms[0] == 'r' && strcmp(entry->pathname, "[vvar]");
}

static int dump_procfs_mem(pid_t pid, maps_entry_t* pid_maps) {
    int mem_fd = -1;
    int region_fd = -1;

    char mem_path[32];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    mem_fd = open(mem_path, O_RDONLY);
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

        region_fd = open(region_name, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
        if (region_fd < 0) {
            fprintf(stderr, 
                    "Error occured while creating a dump file %s\n", 
                    region_name);
            goto cleanup;
        }

        size_t len = curr->end_addr - curr->start_addr;
        size_t offset = 0;
        char buf[CHUNK_SIZE];

        while (offset < len) {
            ssize_t read_sz = (len - offset) > CHUNK_SIZE ? CHUNK_SIZE : len - offset;

            read_sz = pread(mem_fd, 
                            buf, 
                            read_sz, 
                            curr->start_addr + offset);

            if (read_sz < 0) {
                fprintf(stderr,
                        "Error occured while reading file /proc/%d/mem\n", 
                        pid);
                goto cleanup;
            }

            ssize_t write_sz = 0;
            ssize_t write_total_sz = 0;
            while (write_total_sz < read_sz) {
                write_sz = write(region_fd, 
                                 buf + write_total_sz, 
                                 read_sz - write_total_sz);
                if (write_sz < 0) {
                    fprintf(stderr,
                            "Error occured while writing to file %s\n",
                            region_name);
                    goto cleanup;
                }

                write_total_sz += write_sz;
            }

            offset += read_sz;
        }

        close(region_fd);

        curr = curr->next;
    }

    close(mem_fd);

    return DUMP_SUCCESS;

cleanup:
    close(mem_fd);
    close(region_fd);

    return DUMP_ERROR;
}
