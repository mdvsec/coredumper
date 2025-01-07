#include "proc_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <sys/procfs.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include "exit_codes.h"

#define stringify(x) #x
#define tostring(x) stringify(x)

#define ALIGN_UP(value, alignment) \
        ((value + (alignment) - 1) & ~((alignment) - 1))

#define PATH_SIZE 4096
#define LINE_SIZE PATH_SIZE + 256
#define CHUNK_SIZE 4096

/*  Each line is formatted as follows:
 *  ffffbddf0000-ffffbdf78000 r-xp 00000000 fd:00 1836518                    /usr/lib/aarch64-linux-gnu/libc.so.6 
 */
#define FORMAT_STRING "%lx-%lx %4s %lx %x:%x %lu %" tostring(PATH_SIZE) "[^\n]"

static int collect_prstatus(const pid_t, const pid_t, prstatus_t*);
static int collect_fpregs(const pid_t, elf_fpregset_t*);
static int collect_arm_pac_mask(const pid_t, elf_arm_pac_mask_t*);
static int collect_siginfo(const pid_t, siginfo_t*);

static int is_readable(const maps_entry_t* entry, const char* pathname) {
    return entry->perms[0] == 'r' && (entry->len ? strcmp(pathname, "[vvar]") : 1);
}

int parse_procfs_maps(const pid_t pid, maps_entry_t** pid_maps) {
    maps_entry_t* tail = *pid_maps;
    FILE* maps_file;
    char line[LINE_SIZE];
    char maps_path[32];
    int ret = 0;

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        return CD_IO_ERR;
    }

    while (fgets(line, sizeof(line), maps_file)) {
        char tmp_pathname[PATH_SIZE + 1] = {0};
        size_t path_len;
        maps_entry_t* maps_entry;
        int matched;

        maps_entry = malloc(sizeof(maps_entry_t));
        if (!maps_entry) {
            ret = CD_NO_MEM;
            goto maps_cleanup;
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
            ret = CD_IO_ERR;
            free(maps_entry);
            goto maps_cleanup;
        }

        path_len = strlen(tmp_pathname);
        maps_entry->len = path_len ? path_len + 1 : 0;

        if (!is_readable(maps_entry, tmp_pathname)) {
            free(maps_entry);
            continue;
        }

        if (maps_entry->len) {
            maps_entry_t* maps_entry_tmp = realloc(maps_entry, 
                                                   offsetof(maps_entry_t, pathname[0]) + maps_entry->len * sizeof(maps_entry->pathname[0]));

            if (!maps_entry_tmp) {
                ret = CD_NO_MEM;
                free(maps_entry);
                goto maps_cleanup;
            }
            
            maps_entry = maps_entry_tmp;
            strcpy(maps_entry->pathname, tmp_pathname);
        }

        if (*pid_maps) {
            tail->next = maps_entry;
            tail = maps_entry;
        } else {
            *pid_maps = tail = maps_entry;
        }

        tail->next = NULL;
    }

    if (ferror(maps_file)) {
        ret = CD_IO_ERR;
        goto maps_cleanup;
    }

    fclose(maps_file);

    return ret;

maps_cleanup:
    free_maps_list(*pid_maps);
    *pid_maps = NULL;
    fclose(maps_file);
    return ret;
}

void free_maps_list(maps_entry_t* head) {
    while (head) {
        maps_entry_t* next = head->next;
        free(head);
        head = next;
    }
}

void print_maps_list(const maps_entry_t* head) {
    while (head) {
        printf("Start addr: %lx\n", head->start_addr);
        printf("End addr: %lx\n", head->end_addr);
        printf("Permissions: %s\n", head->perms);
        printf("Offset: %lx\n", head->offset);
        printf("Dev major: %x\n", head->dev_major);
        printf("Dev minor: %x\n", head->dev_minor);
        printf("Inode: %lu\n", head->inode);

        if (head->len) {
            printf("Pathname: %s\n", head->pathname);
        } else {
            printf("Pathname: [anonymous]\n");
        }

        head = head->next;
    }
}

int dump_memory_region(const int fd, size_t* data_offset, const Elf64_Phdr* phdr, const pid_t pid) {
    int mem_fd;
    size_t len;
    size_t offset;
    char mem_path[32];
    char buf[CHUNK_SIZE] = {0};

    if (lseek(fd, *data_offset, SEEK_SET) < 0) {
        return CD_IO_ERR;
    }

    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        return CD_IO_ERR;
    }

    len = phdr->p_memsz;
    offset = 0;

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
                goto dump_cleanup;
            }
        }

        while (write_total_sz < read_sz) {
            write_sz = write(fd,
                             buf + write_total_sz,
                             read_sz - write_total_sz);
            if (write_sz < 0) {
                goto dump_cleanup;
            }

            write_total_sz += write_sz;
        }

        offset += read_sz;
    }

    *data_offset += len;
    *data_offset = ALIGN_UP(*data_offset, phdr->p_align);

    close(mem_fd);

    return 0;

dump_cleanup:
    close(mem_fd);
    return CD_IO_ERR;
}

int collect_threads_state(const pid_t pid, thread_state_t** head) {
    thread_state_t* tail = *head;
    char task_path[64];
    DIR* task_dir;
    struct dirent* entry;
    int ret;

    if (*head) {
        return CD_INVALID_ARGS;
    }

    snprintf(task_path, sizeof(task_path), "/proc/%d/task", pid);

    task_dir = opendir(task_path);
    if (!task_dir) {
        return CD_IO_ERR;
    }

    while ((entry = readdir(task_dir))) {
        pid_t tid;
        thread_state_t* state;

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        tid = atoi(entry->d_name);

        if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) < 0) {
            ret = CD_PTRACE_ERR;
            goto state_cleanup;
        }

        if (waitpid(tid, NULL, 0) < 0) {
            ret = CD_PTRACE_ERR;
            goto state_cleanup;
        }

        state = malloc(sizeof(thread_state_t));
        if (!state) {
            ret = CD_NO_MEM;
            goto state_cleanup;
        }

        if ((ret = collect_prstatus(pid, tid, &state->prstatus))) {
            free(state);
            goto state_cleanup;
        }

        if ((ret = collect_fpregs(tid, &state->fpregs))) {
            free(state);
            goto state_cleanup;
        }

        if ((ret = collect_arm_pac_mask(tid, &state->pac_mask))) {
            free(state);
            goto state_cleanup;
        }

        if ((ret = collect_siginfo(tid, &state->siginfo))) {
            free(state);
            goto state_cleanup;
        }

        if (ptrace(PTRACE_DETACH, tid, NULL, NULL) < 0) {
            free(state);
            ret = CD_PTRACE_ERR;
            goto state_cleanup;
        }

        if (*head) {
            tail->next = state;
        } else {
            *head = state;
        }

        tail = state;
        tail->next = NULL;
    }

    closedir(task_dir);

    return ret;

state_cleanup:
    free_state_list(*head);
    *head = NULL;
    closedir(task_dir);

    return ret;
}

void free_state_list(thread_state_t* head) {
    while (head) {
        thread_state_t* next = head->next;
        free(head);
        head = next;
    }
}

void print_state_list(const thread_state_t* head) {
    while (head) {
        /* print debug messages */
        head = head->next;
    }
}

static int populate_prstatus(const pid_t pid, const pid_t tid, prstatus_t* prstatus) {
    FILE* status_file;
    char status_path[32];
    char line[LINE_SIZE];

    snprintf(status_path, sizeof(status_path), "/proc/%d/task/%d/status", pid, tid);

    status_file = fopen(status_path, "r");
    if (!status_file) {
        return CD_IO_ERR;
    }

    while (fgets(line, sizeof(line), status_file)) {
        if (strncmp(line, "SigPnd:", 7) == 0) {
            sscanf(line, "SigPnd: %lx", &prstatus->pr_sigpend);
            continue;
        }

        if (strncmp(line, "SigBlk:", 7) == 0) {
            sscanf(line, "SigBlk: %lx", &prstatus->pr_sighold);
            continue;
        }

        if (strncmp(line, "Pid:", 4) == 0) {
            sscanf(line, "Pid: %d", &prstatus->pr_pid);
            continue;
        }

        if (strncmp(line, "PPid:", 5) == 0) {
            sscanf(line, "PPid: %d", &prstatus->pr_ppid);
            continue;
        }
    }

    if (ferror(status_file)) {
        fclose(status_file);
        return CD_IO_ERR;
    }

    fclose(status_file);

    return 0;
}

static int collect_prstatus(const pid_t pid, const pid_t tid, prstatus_t* prstatus) {
    struct iovec iov;
    int ret;

    memset(prstatus, 0, sizeof(*prstatus));

    /* Signal may be absent */
    ptrace(PTRACE_GETSIGINFO, tid, NULL, &prstatus->pr_info);
    prstatus->pr_cursig = prstatus->pr_info.si_signo;

    if ((ret = populate_prstatus(pid, tid, prstatus))) {
        return ret;
    }

    iov.iov_base = &prstatus->pr_reg;
    iov.iov_len = sizeof(prstatus->pr_reg);
    if (ptrace(PTRACE_GETREGSET, tid, (void*) NT_PRSTATUS, &iov) < 0) {
        return CD_PTRACE_ERR;
    }

    prstatus->pr_fpvalid = 1;

    return ret;
}

static int collect_fpregs(const pid_t tid, elf_fpregset_t* fpregs) {
    struct iovec iov;

    memset(fpregs, 0, sizeof(*fpregs));

    iov.iov_base = fpregs;
    iov.iov_len = sizeof(*fpregs);

    if (ptrace(PTRACE_GETREGSET, tid, (void*) NT_FPREGSET, &iov) < 0) {
        perror("ptrace_getregset");
        return CD_PTRACE_ERR;
    }

    return 0;
}

static int collect_siginfo(const pid_t tid, siginfo_t* siginfo) {
    memset(siginfo, 0, sizeof(*siginfo));

    /* Signals may be absent */
    ptrace(PTRACE_GETSIGINFO, tid, NULL, siginfo);

    return 0;
}

static int collect_arm_pac_mask(const pid_t tid, elf_arm_pac_mask_t* mask) {
    struct iovec iov;

    memset(mask, 0, sizeof(*mask));

    iov.iov_base = mask;
    iov.iov_len = sizeof(*mask);

    if (ptrace(PTRACE_GETREGSET, tid, (void*) NT_ARM_PAC_MASK, &iov) < 0) {
        return CD_PTRACE_ERR;
    }

    return 0;
}

int collect_nt_prpsinfo(const pid_t pid, prpsinfo_t* info) {
    FILE* status_file = NULL;
    FILE* cmdline_file = NULL;
    char status_path[32];
    char cmdline_path[32];
    char line[LINE_SIZE] = {0};
    size_t len;

    snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);

    status_file = fopen(status_path, "r");
    if (!status_file) {
        return CD_IO_ERR;
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
            sscanf(line, "Uid: %u", &info->pr_uid);
            continue;
        }

        if (strncmp(line, "Gid:", 4) == 0) {
            sscanf(line, "Gid: %u", &info->pr_gid);
            continue;
        }
    }

    if (ferror(status_file)) {
        goto prpsinfo_cleanup;
    }

    cmdline_file = fopen(cmdline_path, "r");
    if (!cmdline_file) {
        goto prpsinfo_cleanup;
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

    if (ferror(cmdline_file)) {
        goto prpsinfo_cleanup;
    }

    fclose(cmdline_file);
    fclose(status_file);

    return 0;

prpsinfo_cleanup:
    fclose(cmdline_file);
    fclose(status_file);
    return CD_IO_ERR;
}

int collect_nt_auxv(const pid_t pid, Elf64_auxv_t** data_buf, size_t* data_sz) {
    int auxv_fd;
    char auxv_path[32];
    char buf[512];
    ssize_t bytes_read;
    size_t total_sz;
    int ret = 0;

    snprintf(auxv_path, sizeof(auxv_path), "/proc/%d/auxv", pid);

    auxv_fd = open(auxv_path, O_RDONLY);
    if (auxv_fd < 0) {
        return CD_IO_ERR;
    }

    if (*data_buf) {
        close(auxv_fd);
        return CD_INVALID_ARGS;
    }

    total_sz = 0;
    bytes_read = 0;

    while ((bytes_read = read(auxv_fd, buf, sizeof(buf))) > 0) {
        Elf64_auxv_t* tmp_buf = realloc(*data_buf, total_sz + bytes_read);
        if (!tmp_buf) {
            ret = CD_NO_MEM;
            goto auxv_cleanup;
        }

        *data_buf = tmp_buf;
        memcpy((char*) *data_buf + total_sz, buf, bytes_read);

        total_sz += bytes_read;
    }

    if (bytes_read < 0 || total_sz == 0) {
        ret = CD_IO_ERR;
        goto auxv_cleanup;
    }

    if (data_sz) {
        *data_sz = total_sz;
    } else {
        ret = CD_INVALID_ARGS;
        goto auxv_cleanup;
    }

    close(auxv_fd);

    return ret;

auxv_cleanup:
    free(*data_buf);
    *data_buf = NULL;
    close(auxv_fd);

    return ret;
}

int collect_nt_file(const maps_entry_t* head, void** data_buf, size_t* data_sz) {
    const maps_entry_t* entry;
    size_t desc_sz;
    size_t region_count;
    size_t region_offset;
    size_t name_offset;
    const char anon_name[] = "[anonymous]";

    desc_sz = sizeof(uint64_t) * 2; /* count, pagesize */
    region_count = 0;

    entry = head;
    while (entry) {
        if (entry->inode) {
            size_t entry_name_len;

            entry_name_len = entry->len ? strlen(entry->pathname) + 1 : sizeof(anon_name);
            desc_sz += sizeof(uint64_t) * 3 + entry_name_len;

            region_count++;
        }

        entry = entry->next;
    }

    if (*data_buf) {
        return CD_INVALID_ARGS;
    }

    *data_buf = malloc(desc_sz);
    if (!*data_buf) {
        return CD_NO_MEM;
    }

    if (data_sz) {
        *data_sz = desc_sz;
    } else {
        return CD_INVALID_ARGS;
    }

    memset(*data_buf, 0, desc_sz);

    *(uint64_t*) *data_buf = (uint64_t) region_count;
    *(uint64_t*) ((char*) *data_buf + sizeof(uint64_t)) = (uint64_t) 1; /* Required by GDB */

    region_offset = sizeof(uint64_t) * 2;
    name_offset = region_offset + region_count * sizeof(uint64_t) * 3;

    entry = head;
    while (entry) {
        if (entry->inode) {
            const char* entry_name;
            size_t entry_name_len;

            *(uint64_t*) ((char*) *data_buf + region_offset) = (uint64_t) entry->start_addr;
            region_offset += sizeof(uint64_t);

            *(uint64_t*) ((char*) *data_buf + region_offset) = (uint64_t) entry->end_addr;
            region_offset += sizeof(uint64_t);

            *(uint64_t*) ((char*) *data_buf + region_offset) = (uint64_t) entry->offset;
            region_offset += sizeof(uint64_t);

            entry_name = entry->len ? entry->pathname : anon_name;
            entry_name_len = strlen(entry_name) + 1;

            strcpy((char*) *data_buf + name_offset, entry_name);
            name_offset += entry_name_len;
        }

        entry = entry->next;
    }

    /*
    const uint64_t* ptr = (const uint64_t*) data_buf;
    uint64_t count = *ptr++;
    uint64_t pgsz = *ptr++;

    printf("Region count: %ld\nPage size: %ld\n", count, pgsz);

    const uint64_t* region_ptr = ptr;

    const char* name_ptr = (const char*) data_buf + sizeof(uint64_t) * 2 + (region_count * sizeof(uint64_t) * 3);

    printf("\nRegions:\n");
    printf("Start Address | End Address | Offset       | Name\n");
    printf("-------------------------------------------------\n");

    for (size_t i = 0; i < region_count; i++) {
        uint64_t start_addr = *region_ptr++;
        uint64_t end_addr = *region_ptr++;
        uint64_t offset = *region_ptr++;

        printf("%12lx | %12lx | %12lx | %s\n", start_addr, end_addr, offset, name_ptr);

        name_ptr += strlen(name_ptr) + 1;
    }

    */

    return 0;
}
