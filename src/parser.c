#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

maps_entry_t* parse_procfs_maps(const pid_t pid) {
    maps_entry_t* pid_maps = NULL;
    maps_entry_t* tail = pid_maps;

    char maps_path[32];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        return NULL; 
    }

    char line[LINE_SIZE];
    char format[64];

    /*  Each line is formatted as follows:
     *  ffffbddf0000-ffffbdf78000 r-xp 00000000 fd:00 1836518                    /usr/lib/aarch64-linux-gnu/libc.so.6 
     */ 
    snprintf(format, sizeof(format), "%%llx-%%llx %%4s %%llx %%x:%%x %%lu %%%d[^\n]", PATH_MAX - 1);

    while (fgets(line, sizeof(line), maps_file)) {
        char tmp_pathname[PATH_MAX] = {0};
        maps_entry_t* maps_entry = malloc(sizeof(maps_entry_t));
        if (!maps_entry) {
            fprintf(stderr,
                    "Not enough memory, aborting\n");
            free_maps_list(pid_maps);
            fclose(maps_file);
            return NULL;
        }

        int matched = sscanf(line, 
                             format,
                             &maps_entry->start_addr,
                             &maps_entry->end_addr,
                             maps_entry->perms,
                             &maps_entry->offset,
                             &maps_entry->dev_major,
                             &maps_entry->dev_minor,
                             &maps_entry->inode,
                             tmp_pathname);

        if (matched < 7) {
            fprintf(stderr,
                    "Error occured while parsing line: %s", 
                    line);
            free_maps_list(pid_maps);
            fclose(maps_file);
            return NULL; 
        }

        size_t path_len = strlen(tmp_pathname);
        if (path_len) {
            maps_entry->len = path_len + 1;
        } else {
            maps_entry->len = 0;
        }

        if (maps_entry->len) {
            maps_entry = realloc(maps_entry, offsetof(maps_entry_t, pathname[0]) + maps_entry->len * sizeof(maps_entry->pathname[0]));

            if (!maps_entry) {
                fprintf(stderr,
                    "Not enough memory, aborting\n");
                free_maps_list(pid_maps);
                fclose(maps_file);
                return NULL;
            }

            strcpy(maps_entry->pathname, tmp_pathname);
        }

        if (pid_maps) {
            tail->next = maps_entry;
            tail = maps_entry;
        } else {
            pid_maps = tail = maps_entry;
        }

        tail->next = NULL;
    }

    // The file may be closed while being read
    if (ferror(maps_file)) {
        fprintf(stderr,
                "Error occured while reading file %s\n",
                maps_path);
        free_maps_list(pid_maps);
        fclose(maps_file);
        return NULL;
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

        if (curr->len) {
            printf("Pathname: %s\n", curr->pathname);
        } else {
            printf("Pathname: [anonymous]\n");
        }

        curr = curr->next;
    }
}


