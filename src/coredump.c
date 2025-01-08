#include "coredump.h"
#include <limits.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "proc_parser.h"
#include "elf_utils.h"
#include "common.h"

int create_coredump(const pid_t pid, const char* filename) {
    maps_entry_t* pid_maps;
    size_t phdr_count;
    int coredump_fd;
    int ret;

    coredump_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC,
                       S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (coredump_fd < 0) {
        LOG("Failed to open %s", filename);
        return CD_IO_ERR;
    }

    pid_maps = NULL;
    ret = parse_procfs_maps(pid, &pid_maps);
    if (ret) {
        goto coredump_cleanup;
    }

    if (!pid_maps) {
        return CD_SPECIAL_PROC;
    }

    phdr_count = 0;
    ret = write_elf_program_headers(coredump_fd, pid_maps, pid, &phdr_count);
    if (ret) {
        goto coredump_cleanup;
    }

    ret = write_elf_header(coredump_fd, phdr_count);
    if (ret) {
        goto coredump_cleanup;
    }

    free_maps_list(pid_maps);
    close(coredump_fd);

    return CD_SUCCESS;

coredump_cleanup:
    free_maps_list(pid_maps);
    close(coredump_fd);

    return ret;
}
