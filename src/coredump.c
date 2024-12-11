#include "coredump.h"
#include <limits.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "parser.h"
#include "elf_utils.h"

int create_coredump(const pid_t pid, const char* filename) {
    maps_entry_t* pid_maps;
    ssize_t phdr_count;
    int coredump_fd;
    int ret;

    coredump_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (coredump_fd < 0) {
        fprintf(stderr,
                "Error occured while creating file %s\n",
                filename);
        return -1;
    }

    pid_maps = parse_procfs_maps(pid);
    if (!pid_maps) {
        fprintf(stderr,
                "Error occured while parsing /proc/%d/maps\n",
                pid);
        close(coredump_fd);
        return -1;
    }

    phdr_count = write_elf_program_headers(coredump_fd, pid_maps, pid);
    if (phdr_count < 0) {
        fprintf(stderr,
                "Error occured while dumping process %d\n",
                pid);
        free_maps_list(pid_maps);
        close(coredump_fd);
        return -1;
    }

    ret = write_elf_header(coredump_fd, phdr_count);
    if (ret < 0) {
        fprintf(stderr,
                "Error occured while writing to file %s\n",
                filename);
        free_maps_list(pid_maps);
        close(coredump_fd);
        return -1;
    }

    free_maps_list(pid_maps);
    close(coredump_fd);

    return 0;
}
