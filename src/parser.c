#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#define stringify(x) #x
#define tostring(x) stringify(x)

#define PATH_SIZE 4096
#define LINE_SIZE PATH_SIZE + 256 

/*  Each line is formatted as follows:
 *  ffffbddf0000-ffffbdf78000 r-xp 00000000 fd:00 1836518                    /usr/lib/aarch64-linux-gnu/libc.so.6 
 */
#define FORMAT_STRING "%lx-%lx %4s %lx %x:%x %lu %" tostring(PATH_SIZE) "[^\n]"

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
    while (fgets(line, sizeof(line), maps_file)) {
        char tmp_pathname[PATH_SIZE + 1] = {0};
        maps_entry_t* maps_entry = malloc(sizeof(maps_entry_t));
        if (!maps_entry) {
            fprintf(stderr,
                    "Not enough memory, aborting\n");
            goto cleanup;
        }

        int matched = sscanf(line, 
                             FORMAT_STRING,
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
            free(maps_entry);
            goto cleanup;
        }

        size_t path_len = strlen(tmp_pathname);
        maps_entry->len = path_len ? path_len + 1 : 0;

        if (maps_entry->len) {
            maps_entry_t* maps_entry_tmp = realloc(maps_entry, 
                                                   offsetof(maps_entry_t, pathname[0]) + maps_entry->len * sizeof(maps_entry->pathname[0]));

            if (!maps_entry_tmp) {
                fprintf(stderr,
                        "Not enough memory, aborting\n");
                free(maps_entry);
                goto cleanup;
            }
            
            maps_entry = maps_entry_tmp;
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
        goto cleanup;
    }

    fclose(maps_file);

    return pid_maps;

cleanup:
    free_maps_list(pid_maps);
    fclose(maps_file);
    return NULL;
}

void free_maps_list(maps_entry_t* head) {
    while (head) {
        maps_entry_t* next = head->next;
        free(head);
        head = next;
    }
}

void print_maps_list(const maps_entry_t* head) {
    const maps_entry_t* curr = head;
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

size_t count_proc_maps(const maps_entry_t* head) {
    size_t count = 0;
    const maps_entry_t* curr = head;
    while (curr) {
        count++;
        curr = curr->next;
    }

    return count;
}
