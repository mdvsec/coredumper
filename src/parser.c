#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int parse_procfs(const pid_t pid) {
    char maps_path[PATH_MAX];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        return -1; 
    }

    char line[LINE_SIZE];
    char format[64];
    snprintf(format, sizeof(format), "%%llx-%%llx %%4s %%llx %%x:%%x %%lu %%%d[^\n]", PATH_MAX - 1);

    while (fgets(line, sizeof(line), maps_file)) {
        maps_entry_t maps_entry;
        maps_entry.pathname[0] = '\0';

        int matched = sscanf(line, 
                             format,
                             &maps_entry.start_addr,
                             &maps_entry.end_addr,
                             maps_entry.perms,
                             &maps_entry.offset,
                             &maps_entry.dev_major,
                             &maps_entry.dev_minor,
                             &maps_entry.inode,
                             maps_entry.pathname);

        if (matched < 7) {
            fprintf(stderr,
                    "Error occured while parsing line: %s", 
                    line);
            return -1; 
        }

        if (maps_entry.pathname[0] == '\0') {
            strncpy(maps_entry.pathname, "[anonymous]", PATH_MAX);
        }

        printf("[DEBUG] Parsed entry\n%s", line);
        printf("Start addr: %lx\n", maps_entry.start_addr);
        printf("End addr: %lx\n", maps_entry.end_addr);
        printf("Permissions: %s\n", maps_entry.perms);
        printf("Offset: %lx\n", maps_entry.offset);
        printf("Dev major: %x\n", maps_entry.dev_major);
        printf("Dev minor: %x\n", maps_entry.dev_minor);
        printf("Inode: %lu\n", maps_entry.inode);
        printf("Pathname: %s\n", maps_entry.pathname);
    }

    fclose(maps_file);

    return EXIT_SUCCESS;
}
