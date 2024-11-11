#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

maps_entry_t* parse_procfs_maps(const pid_t pid) {
    maps_entry_t* pid_maps = NULL;
    maps_entry_t* tail = pid_maps;

    char maps_path[PATH_MAX];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        return NULL; 
    }

    char line[LINE_SIZE];
    char format[64];

    /*  Each line is formatted as follows:
     * ffffbddf0000-ffffbdf78000 r-xp 00000000 fd:00 1836518                    /usr/lib/aarch64-linux-gnu/libc.so.6 
     */ 
    snprintf(format, sizeof(format), "%%llx-%%llx %%4s %%llx %%x:%%x %%lu %%%d[^\n]", PATH_MAX - 1);

    while (fgets(line, sizeof(line), maps_file)) {
        maps_entry_t* maps_entry = malloc(sizeof(maps_entry_t));
        if (!maps_entry) {
            fprintf(stderr,
                    "Not enough memory, aborting\n");
            free_maps_list(pid_maps);
            fclose(maps_file);
            return NULL;
        }

        maps_entry->pathname[0] = '\0';
        int matched = sscanf(line, 
                             format,
                             &maps_entry->start_addr,
                             &maps_entry->end_addr,
                             maps_entry->perms,
                             &maps_entry->offset,
                             &maps_entry->dev_major,
                             &maps_entry->dev_minor,
                             &maps_entry->inode,
                             maps_entry->pathname);

        if (matched < 7) {
            fprintf(stderr,
                    "Error occured while parsing line: %s", 
                    line);
            free_maps_list(pid_maps);
            fclose(maps_file);
            return NULL; 
        }

        if (maps_entry->pathname[0] == '\0') {
            strncpy(maps_entry->pathname, "[anonymous]", PATH_MAX);
        }

        if (pid_maps) {
            tail->next = maps_entry;
            tail = maps_entry;
        } else {
            pid_maps = tail = maps_entry;
        }

        tail->next = NULL;
    }

    fclose(maps_file);

    return pid_maps;
}

void free_maps_list(maps_entry_t* head) {
    while (head) {
        maps_entry_t* next = head->next;
        free(head);
        head = next;
    }
}

void print_maps_list(maps_entry_t* head) {
    maps_entry_t* curr = head;
    while (curr) {
        printf("Start addr: %lx\n", curr->start_addr);
        printf("End addr: %lx\n", curr->end_addr);
        printf("Permissions: %s\n", curr->perms);
        printf("Offset: %lx\n", curr->offset);
        printf("Dev major: %x\n", curr->dev_major);
        printf("Dev minor: %x\n", curr->dev_minor);
        printf("Inode: %lu\n", curr->inode);
        printf("Pathname: %s\n", curr->pathname);

        curr = curr->next;
    }
}


