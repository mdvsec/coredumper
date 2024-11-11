#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <limits.h>
#include <sys/types.h>

/*
 *   Defines the buffer size for reading lines from the /proc/PID/maps file.
 *   The last field in each line may contain an absolute file path, thus PATH_MAX, 
 *   and 256 is an arbitrary value chosen to account all other fields.
 */
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
    struct _maps_entry_t* next;
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

void free_maps_list(maps_entry_t*);
void print_maps_list(maps_entry_t*);

#endif
