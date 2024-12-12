#include "proc_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <sys/procfs.h>

#define stringify(x) #x
#define tostring(x) stringify(x)

#define PATH_SIZE 4096
#define LINE_SIZE PATH_SIZE + 256
#define CHUNK_SIZE 4096

/*  Each line is formatted as follows:
 *  ffffbddf0000-ffffbdf78000 r-xp 00000000 fd:00 1836518                    /usr/lib/aarch64-linux-gnu/libc.so.6 
 */
#define FORMAT_STRING "%lx-%lx %4s %lx %x:%x %lu %" tostring(PATH_SIZE) "[^\n]"

extern ssize_t data_offset;

maps_entry_t* parse_procfs_maps(const pid_t pid) {
    maps_entry_t* pid_maps = NULL;
    maps_entry_t* tail = pid_maps;

    FILE* maps_file;
    char line[LINE_SIZE];

    char maps_path[32];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        return NULL; 
    }

    while (fgets(line, sizeof(line), maps_file)) {
        char tmp_pathname[PATH_SIZE + 1] = {0};
        size_t path_len;
        maps_entry_t* maps_entry;
        int matched;

        maps_entry = malloc(sizeof(maps_entry_t));
        if (!maps_entry) {
            fprintf(stderr,
                    "Not enough memory, aborting\n");
            goto cleanup;
        }

        matched = sscanf(line,
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

        path_len = strlen(tmp_pathname);
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
    const maps_entry_t* entry = head;
    while (entry) {
        printf("Start addr: %lx\n", entry->start_addr);
        printf("End addr: %lx\n", entry->end_addr);
        printf("Permissions: %s\n", entry->perms);
        printf("Offset: %lx\n", entry->offset);
        printf("Dev major: %x\n", entry->dev_major);
        printf("Dev minor: %x\n", entry->dev_minor);
        printf("Inode: %lu\n", entry->inode);

        if (entry->len) {
            printf("Pathname: %s\n", entry->pathname);
        } else {
            printf("Pathname: [anonymous]\n");
        }

        entry = entry->next;
    }
}

int dump_memory_region(const int fd, const Elf64_Phdr* phdr, const pid_t pid) {
    int mem_fd;
    size_t len;
    size_t offset;
    char mem_path[32];
    char buf[CHUNK_SIZE];

    if (lseek(fd, data_offset, SEEK_SET) < 0) {
        return -1;
    }

    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        return -1;
    }

    len = phdr->p_memsz;
    offset = 0;

    memset(buf, 0, sizeof(buf));
    while (offset < len) {
        ssize_t read_sz = (len - offset) > CHUNK_SIZE ? CHUNK_SIZE : len - offset;
        ssize_t write_sz = 0;
        ssize_t write_total_sz = 0;

        if (phdr->p_flags & PF_R) {
            read_sz = pread(mem_fd,
                            buf,
                            read_sz,
                            phdr->p_vaddr + offset);

            if (read_sz < 0) {
                goto cleanup;
            }
        }

        while (write_total_sz < read_sz) {
            write_sz = write(fd,
                             buf + write_total_sz,
                             read_sz - write_total_sz);
            if (write_sz < 0) {
                goto cleanup;
            }

            write_total_sz += write_sz;
        }

        offset += read_sz;
    }

    data_offset += len;
    data_offset = (data_offset + phdr->p_align - 1) & ~(phdr->p_align - 1);

    close(mem_fd);

    return 0;

cleanup:
    close(mem_fd);
    return -1;
}

int collect_nt_prpsinfo(const pid_t pid, prpsinfo_t* info) {
    FILE* status_file;
    FILE* cmdline_file;
    char status_path[32];
    char cmdline_path[32];
    char line[LINE_SIZE];
    size_t len;

    snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);

    status_file = fopen(status_path, "r");
    if (!status_file) {
        return -1;
    }

    memset(info, 0, sizeof(*info));

    while (fgets(line, sizeof(line), status_file)) {
        if (strncmp(line, "Name:", 5) == 0) {
            sscanf(line, "Name: %15s", info->pr_fname);
            continue;
        }

        if (strncmp(line, "State:", 6) == 0) {
            sscanf(line, "State: %c", &info->pr_sname);
            info->pr_zomb = (info->pr_sname == 'Z') ? 1 : 0;
            info->pr_state = info->pr_sname;
            continue;
        }

        if (strncmp(line, "Pid:", 4) == 0) {
            sscanf(line, "Pid: %d", &info->pr_pid);
            continue;
        }

        if (strncmp(line, "PPid:", 5) == 0) {
            sscanf(line, "PPid: %d", &info->pr_ppid);
            continue;
        }

        if (strncmp(line, "Uid:", 4) == 0) {
            sscanf(line, "Uid: %d", &info->pr_uid);
            continue;
        }

        if (strncmp(line, "Gid:", 4) == 0) {
            sscanf(line, "Gid: %d", &info->pr_gid);
            continue;
        }
    }

    cmdline_file = fopen(cmdline_path, "r");
    if (!cmdline_file) {
        fclose(status_file);
        return -1;
    }

    memset(line, 0, sizeof(line));
    len = fread(line, 1, sizeof(line), cmdline_file);
    if (len) {
        for (size_t i = 0; i < len; i++) {
            if (line[i] == 0) {
                line[i] = ' ';
            }
        }

        strncpy(info->pr_psargs, line, sizeof(info->pr_psargs) - 1);
        info->pr_psargs[sizeof(info->pr_psargs) - 1] = 0;
    }

    /*
    printf("DEBUG\nName:%s\nState:%c\nPid:%d\nArgs:%s\n",
           info->pr_fname,
           info->pr_sname,
           info->pr_pid,
           info->pr_psargs);
    */

    fclose(cmdline_file);
    fclose(status_file);

    return 0;
}
