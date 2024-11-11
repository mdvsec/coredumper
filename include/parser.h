#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <limits.h>
#include <sys/types.h>

#define LINE_SIZE PATH_MAX + 256 

typedef struct _maps_entry_t {
    uint64_t start_addr;
    uint64_t end_addr;
    char perms[5];
    uint64_t offset;
    int dev_major;
    int dev_minor;
    uint64_t inode;
    char pathname[PATH_MAX];
} maps_entry_t;

int parse_procfs(const pid_t);

#endif
