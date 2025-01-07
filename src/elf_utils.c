#include "elf_utils.h"
#include <stddef.h>
#include <elf.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/procfs.h>
#include <sys/uio.h>
#include "proc_parser.h"
#include "exit_codes.h"

#define PAGE_SIZE_DEFAULT 4096
#define PT_NOTE_ALIGNMENT 4

#define PADDING_COUNT(value, padding) \
        (((value + padding - 1) & ~(padding - 1)) - value)

static int dump_process_memory(const int, size_t*, size_t*, const maps_entry_t*, const pid_t, int*);
static int dump_process_info(const int, size_t*, size_t*, const maps_entry_t*, const pid_t, int*);

static int write_generic_note(const int, size_t*, size_t*, const void*, const size_t, const int, const char*, int*);
static int write_note_data(const int, const size_t*, const void*, const size_t, const int, const char*, size_t*);
static int write_threads_state(const int, size_t*, size_t*, const thread_state_t*, int*);
static int write_phdr_entry(const int, size_t*, const Elf64_Phdr*);

static void create_program_header_ptload(Elf64_Phdr*, const maps_entry_t*, const size_t*);
static void create_program_header_ptnote(Elf64_Phdr*, const size_t, const size_t*);

static size_t get_pagesize(void) {
    static size_t cached_pagesize = 0;

    if (cached_pagesize == 0) {
        long pagesize = sysconf(_SC_PAGESIZE);
        cached_pagesize = (pagesize > 0) ? (size_t) pagesize : PAGE_SIZE_DEFAULT;
    }

    return cached_pagesize;
}

int write_elf_header(const int fd, const ssize_t phdr_count) {
    if (lseek(fd, 0, SEEK_SET) < 0) {
        return CD_IO_ERR;
    }

    Elf64_Ehdr elf_hdr;
    memset(&elf_hdr, 0, sizeof(elf_hdr));

    elf_hdr.e_ident[EI_MAG0] = ELFMAG0;
    elf_hdr.e_ident[EI_MAG1] = ELFMAG1;
    elf_hdr.e_ident[EI_MAG2] = ELFMAG2;
    elf_hdr.e_ident[EI_MAG3] = ELFMAG3;

    elf_hdr.e_ident[EI_CLASS] = ELFCLASS64;
    elf_hdr.e_ident[EI_DATA] = ELFDATA2LSB;
    elf_hdr.e_ident[EI_VERSION] = EV_CURRENT;
    elf_hdr.e_ident[EI_OSABI] = ELFOSABI_NONE;
    elf_hdr.e_ident[EI_ABIVERSION] = 0;

    elf_hdr.e_type = ET_CORE;
    elf_hdr.e_machine = EM_AARCH64;
    elf_hdr.e_version = EV_CURRENT;
    elf_hdr.e_phoff = sizeof(Elf64_Ehdr); 
    elf_hdr.e_ehsize = sizeof(Elf64_Ehdr);
    elf_hdr.e_phentsize = sizeof(Elf64_Phdr);
    elf_hdr.e_phnum = phdr_count;

    if (write(fd, &elf_hdr, sizeof(elf_hdr)) != sizeof(elf_hdr)) {
        return CD_IO_ERR;
    }

    return 0;
}

int write_elf_program_headers(const int fd, const maps_entry_t* head, const pid_t pid, size_t* phdr_count) {
    int ptload_hdr_count;
    int ptnote_hdr_count;
    size_t table_offset;
    size_t data_offset;
    off_t seek_result;
    int ret;

    /* Reserve space for ELF header */
    seek_result = lseek(fd, sizeof(Elf64_Ehdr), SEEK_SET);
    if (seek_result < 0) {
        return CD_IO_ERR;
    }
    table_offset = (size_t) seek_result;

    /* TBD: Data offset should be calculated based on number of program headers */
    data_offset = getpagesize();

    ptload_hdr_count = 0;
    ret = dump_process_memory(fd, &table_offset, &data_offset, head, pid, &ptload_hdr_count);
    if (ret) {
        return ret;
    }

    ptnote_hdr_count = 0;
    ret = dump_process_info(fd, &table_offset, &data_offset, head, pid, &ptnote_hdr_count);
    if (ret) {
        return ret;
    }

    *phdr_count = ptload_hdr_count + ptnote_hdr_count;

    return 0;
}

static int dump_process_memory(const int fd, size_t* table_offset, size_t* data_offset, const maps_entry_t* head, const pid_t pid, int* ptload_hdr_count) {
    int ret;

    while (head) {
        Elf64_Phdr phdr;

        create_program_header_ptload(&phdr, head, data_offset);

        ret = write_phdr_entry(fd, table_offset, &phdr);
        if (ret) {
            return ret;
        }

        ret = dump_memory_region(fd, data_offset, &phdr, pid);
        if (ret) {
            return ret;
        }

        (*ptload_hdr_count)++;

        head = head->next;
    }

    return ret;
}

static int dump_process_info(const int fd, size_t* table_offset, size_t* data_offset, const maps_entry_t* head, const pid_t pid, int* ptnote_hdr_count) {
    prpsinfo_t prpsinfo;
    thread_state_t* threads_state;
    Elf64_auxv_t* auxv_buf;
    size_t auxv_sz;
    void* nt_file_buf;
    size_t nt_file_sz;
    int ret;

    threads_state = NULL;
    auxv_buf = NULL;
    nt_file_buf = NULL;
    auxv_sz = nt_file_sz = 0;

    if ((ret = collect_nt_prpsinfo(pid, &prpsinfo))) {
        return ret;
    }

    ret = write_generic_note(fd, table_offset, data_offset, &prpsinfo, sizeof(prpsinfo), NT_PRPSINFO, "CORE", ptnote_hdr_count);
    if (ret) {
        return ret;
    }

    if ((ret = collect_threads_state(pid, &threads_state))) {
        return ret;
    }

    ret = write_threads_state(fd, table_offset, data_offset, threads_state, ptnote_hdr_count);
    if (ret) {
        goto proc_cleanup;
    }

    if ((ret = collect_nt_auxv(pid, &auxv_buf, &auxv_sz))) {
        goto proc_cleanup;
    }

    ret = write_generic_note(fd, table_offset, data_offset, auxv_buf, auxv_sz, NT_AUXV, "CORE", ptnote_hdr_count);
    if (ret) {
        goto proc_cleanup;
    }

    if ((ret = collect_nt_file(head, &nt_file_buf, &nt_file_sz))) {
        goto proc_cleanup;
    }

    ret = write_generic_note(fd, table_offset, data_offset, nt_file_buf, nt_file_sz, NT_FILE, "CORE", ptnote_hdr_count);
    if (ret) {
        goto proc_cleanup;
    }

    free(nt_file_buf);
    free(auxv_buf);
    free_state_list(threads_state);

    return 0;

proc_cleanup:
    free(nt_file_buf);
    free(auxv_buf);
    free_state_list(threads_state);

    return ret;
}

static int write_generic_note(const int fd, size_t* table_offset, size_t* data_offset, const void* buf, const size_t buf_sz, const int type, const char* name, int* ptnote_hdr_count) {
    Elf64_Phdr phdr;
    size_t write_sz;
    int ret;

    write_sz = 0;
    ret = write_note_data(fd, data_offset, buf, buf_sz, type, name, &write_sz);
    if (ret) {
        return ret;
    }

    create_program_header_ptnote(&phdr, write_sz, data_offset);
    if ((ret = write_phdr_entry(fd, table_offset, &phdr))) {
        return ret;
    }

    *data_offset += write_sz;
    (*ptnote_hdr_count)++;

    return ret;
}

static int write_note_data(const int fd, const size_t* data_offset, const void* data, const size_t data_len, const int type, const char* name, size_t* write_sz) {
    Elf64_Nhdr nhdr;
    size_t name_len;
    size_t name_len_padding;
    size_t data_len_padding;
    ssize_t note_sz;
    struct iovec iov[5];
    char p_bytes[PT_NOTE_ALIGNMENT] = {0};

    name_len = strlen(name) + 1;

    name_len_padding = PADDING_COUNT(name_len, PT_NOTE_ALIGNMENT);
    data_len_padding = PADDING_COUNT(data_len, PT_NOTE_ALIGNMENT);

    note_sz = sizeof(nhdr) + name_len + name_len_padding + data_len + data_len_padding;

    memset(&nhdr, 0, sizeof(nhdr));
    nhdr.n_namesz = name_len;
    nhdr.n_descsz = data_len;
    nhdr.n_type = type;

    memset(iov, 0, sizeof(iov));
    iov[0].iov_base = &nhdr;
    iov[0].iov_len = sizeof(nhdr);

    iov[1].iov_base = (void*) name;
    iov[1].iov_len = name_len;

    iov[2].iov_base = p_bytes;
    iov[2].iov_len = name_len_padding;

    iov[3].iov_base = (void*) data;
    iov[3].iov_len = data_len;

    iov[4].iov_base = p_bytes;
    iov[4].iov_len = data_len_padding;

    if (lseek(fd, *data_offset, SEEK_SET) < 0) {
        return CD_IO_ERR;
    }

    if (writev(fd, iov, 5) != note_sz) {
        return CD_IO_ERR;
    }

    *write_sz = note_sz;

    return 0;
}

static int write_threads_state(const int fd, size_t* table_offset, size_t* data_offset, const thread_state_t* head, int* ptnote_hdr_count) {
    size_t note_sz;

    while (head) {
        Elf64_Phdr phdr;
        size_t tmp_data_offset;
        size_t write_sz;
        int ret;

        write_sz = 0;
        note_sz = 0;

        tmp_data_offset = *data_offset + note_sz;
        ret = write_note_data(fd, &tmp_data_offset, &head->prstatus, sizeof(head->prstatus), NT_PRSTATUS, "CORE", &write_sz);
        if (ret) {
            return ret;
        }
        note_sz += write_sz;

        tmp_data_offset = *data_offset + note_sz;
        ret = write_note_data(fd, &tmp_data_offset, &head->fpregs, sizeof(head->fpregs), NT_FPREGSET, "CORE", &write_sz);
        if (ret) {
            return ret;
        }
        note_sz += write_sz;

        tmp_data_offset = *data_offset + note_sz;
        ret = write_note_data(fd, &tmp_data_offset, &head->pac_mask, sizeof(head->pac_mask), NT_ARM_PAC_MASK, "LINUX", &write_sz);
        if (ret) {
            return ret;
        }
        note_sz += write_sz;

        tmp_data_offset = *data_offset + note_sz;
        ret = write_note_data(fd, &tmp_data_offset, &head->siginfo, sizeof(head->siginfo), NT_SIGINFO, "CORE", &write_sz);
        if (ret) {
            return ret;
        }
        note_sz += write_sz;

        create_program_header_ptnote(&phdr, note_sz, data_offset);
        if ((ret = write_phdr_entry(fd, table_offset, &phdr))) {
            return ret;
        }

        *data_offset += note_sz;

        (*ptnote_hdr_count)++;

        head = head->next;
    }

    return 0;
}

static int write_phdr_entry(const int fd, size_t* table_offset, const Elf64_Phdr* phdr) {
    if (lseek(fd, *table_offset, SEEK_SET) < 0) {
        return CD_IO_ERR;
    }

    if (write(fd, phdr, sizeof(*phdr)) != sizeof(*phdr)) {
        return CD_IO_ERR;
    }

    *table_offset += sizeof(*phdr);

    return 0;
}

static void create_program_header_ptload(Elf64_Phdr* phdr, const maps_entry_t* entry, const size_t* data_offset) {
    memset(phdr, 0, sizeof(*phdr));

    phdr->p_type = PT_LOAD;
    phdr->p_vaddr = entry->start_addr;
    phdr->p_paddr = 0;
    phdr->p_filesz = entry->end_addr - entry->start_addr;
    phdr->p_memsz = phdr->p_filesz;

    if (strchr(entry->perms, 'r')) {
        phdr->p_flags |= PF_R;
    }
    if (strchr(entry->perms, 'w')) {
        phdr->p_flags |= PF_W;
    }
    if (strchr(entry->perms, 'x')) {
        phdr->p_flags |= PF_X;
    }

    phdr->p_align = get_pagesize();
    phdr->p_offset = *data_offset;
}

static void create_program_header_ptnote(Elf64_Phdr* phdr, const size_t note_sz, const size_t* data_offset) {
    memset(phdr, 0, sizeof(*phdr));

    phdr->p_type = PT_NOTE;
    phdr->p_vaddr = 0;
    phdr->p_paddr = 0;
    phdr->p_filesz = note_sz;
    phdr->p_memsz = 0;
    phdr->p_flags = 0;
    phdr->p_align = PT_NOTE_ALIGNMENT;
    phdr->p_offset = *data_offset;
}
