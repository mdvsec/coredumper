#ifndef PROC_PARSER_H
#define PROC_PARSER_H

#include <stdint.h>
#include <limits.h>
#include <sys/types.h>
#include <elf.h>

typedef struct _maps_entry_t {
    uintptr_t start_addr;
    uintptr_t end_addr;
    char perms[5];
    uint64_t offset;
    int dev_major;
    int dev_minor;
    uint64_t inode;
    size_t len;
    struct _maps_entry_t* next;
    char pathname[];
} maps_entry_t;

/*
 *   Parses the /proc/PID/maps file and returns a pointer to a linked list
 *   of maps_entry_t structures. Each node in the linked list represents 
 *   an entry from the maps file, with fields populated accordingly.
 *
 *   The caller is responsible for freeing allocated memory for the linked list.
 *
 *   Returns:
 *       A pointer to the head of the linked list containing parsed entries, 
 *       or NULL if an error occurs during parsing.
 */
maps_entry_t* parse_procfs_maps(const pid_t);

int dump_memory_region(const int, const Elf64_Phdr*, const pid_t);

void free_maps_list(maps_entry_t*);
void print_maps_list(const maps_entry_t*);
size_t count_proc_maps(const maps_entry_t*);

#endif
