#ifndef PROC_PARSER_H
#define PROC_PARSER_H

#include <stdint.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/procfs.h>
#include <sys/uio.h>
#include <signal.h>
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

typedef struct {
    uint64_t apiakey_lo;
    uint64_t apiakey_hi;
} elf_arm_pac_mask_t;

typedef struct _thread_state_t {
    prstatus_t prstatus;
    elf_fpregset_t fpregs;
    elf_arm_pac_mask_t pac_mask;
    siginfo_t siginfo;
    struct _thread_state_t* next;
} thread_state_t;

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
int collect_nt_prpsinfo(const pid_t, prpsinfo_t*);
thread_state_t* collect_threads_state(const pid_t);

void free_maps_list(maps_entry_t*);
void print_maps_list(const maps_entry_t*);

void free_state_list(thread_state_t*);
void print_state_list(const thread_state_t*);

#endif
