#include "elf_utils.h"
#include <stddef.h>
#include <elf.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/procfs.h>
#include <sys/uio.h>
#include "proc_parser.h"

#define PAGE_SIZE_DEFAULT 4096
#define PT_NOTE_ALIGNMENT 4

#define PADDING_COUNT(value, padding) \
        (((value + padding - 1) & ~(padding - 1)) - value)

static ssize_t dump_process_memory(const int, size_t*, size_t*, const maps_entry_t*, const pid_t);
static ssize_t dump_process_info(const int, size_t*, size_t*, const maps_entry_t*, const pid_t);
static ssize_t write_generic_note(const int, size_t*, size_t*, const void*, const size_t, const int, const char*);
static ssize_t write_threads_state(const int, size_t*, size_t*, const thread_state_t*);
static ssize_t write_note_data(const int, const size_t*, const void*, const size_t, const int, const char*);
static void create_program_header_ptload(Elf64_Phdr*, const maps_entry_t*, const size_t* data_offset);
static void create_program_header_ptnote(Elf64_Phdr*, const size_t, const size_t*);
static int write_phdr_entry(const int, size_t*, const Elf64_Phdr*);
static long get_pagesize(void);

int write_elf_header(const int fd, const ssize_t phdr_count) {
    if (lseek(fd, 0, SEEK_SET) < 0) {
        return -1;
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
        return -1;
    }

    return 0;
}

ssize_t write_elf_program_headers(const int fd, const maps_entry_t* head, const pid_t pid) {
    ssize_t ptload_hdr_count;
    ssize_t ptnote_hdr_count;
    size_t table_offset;
    size_t data_offset;

    /* Reserve space for ELF header */
    table_offset = lseek(fd, sizeof(Elf64_Ehdr), SEEK_SET);
    if (table_offset < 0) {
        return -1;
    }
    data_offset = getpagesize();

    ptload_hdr_count = dump_process_memory(fd, &table_offset, &data_offset, head, pid);
    if (ptload_hdr_count < 0) {
        return -1;
    }

    ptnote_hdr_count = dump_process_info(fd, &table_offset, &data_offset, head, pid);
    if (ptnote_hdr_count < 0) {
        return -1;
    }

    return ptload_hdr_count + ptnote_hdr_count;
}

static ssize_t dump_process_memory(const int fd, size_t* table_offset, size_t* data_offset, const maps_entry_t* head, const pid_t pid) {
    const maps_entry_t* entry;
    ssize_t ptload_hdr_count;

    ptload_hdr_count = 0;
    entry = head;

    while (entry) {
        Elf64_Phdr phdr;

        create_program_header_ptload(&phdr, entry, data_offset);

        if (write_phdr_entry(fd, table_offset, &phdr) < 0) {
            return -1;
        }

        if (dump_memory_region(fd, data_offset, &phdr, pid) < 0) {
            return -1;
        }

        ptload_hdr_count++;
        entry = entry->next;
    }

    return ptload_hdr_count;
}

static ssize_t dump_process_info(const int fd, size_t* table_offset, size_t* data_offset, const maps_entry_t* head, const pid_t pid) {
    prpsinfo_t prpsinfo;
    thread_state_t* threads_state;
    Elf64_auxv_t* auxv_buf;
    size_t auxv_sz;
    void* nt_file_buf;
    size_t nt_file_sz;
    ssize_t ptnote_hdr_count;
    int written_hdr;

    ptnote_hdr_count = 0;
    threads_state = NULL;
    auxv_buf = NULL;
    nt_file_buf = NULL;
    auxv_sz = nt_file_sz = 0;

    if (collect_nt_prpsinfo(pid, &prpsinfo) < 0) {
        return -1;
    }

    written_hdr = write_generic_note(fd, table_offset, data_offset, &prpsinfo, sizeof(prpsinfo), NT_PRPSINFO, "CORE");
    if (written_hdr < 0) {
        return -1;
    }
    ptnote_hdr_count += written_hdr;

    if (collect_threads_state(pid, &threads_state) < 0) {
        return -1;
    }

    written_hdr = write_threads_state(fd, table_offset, data_offset, threads_state);
    if (written_hdr < 0) {
        goto proc_cleanup;
    }
    ptnote_hdr_count += written_hdr;

    if (collect_nt_auxv(pid, &auxv_buf, &auxv_sz) < 0) {
        goto proc_cleanup;
    }

    written_hdr = write_generic_note(fd, table_offset, data_offset, auxv_buf, auxv_sz, NT_AUXV, "CORE");
    if (written_hdr < 0) {
        goto proc_cleanup;
    }
    ptnote_hdr_count += written_hdr;

    if (collect_nt_file(head, &nt_file_buf, &nt_file_sz) < 0) {
        goto proc_cleanup;
    }

    written_hdr = write_generic_note(fd, table_offset, data_offset, nt_file_buf, nt_file_sz, NT_FILE, "CORE");
    if (written_hdr < 0) {
        goto proc_cleanup;
    }
    ptnote_hdr_count += written_hdr;

    free(nt_file_buf);
    free(auxv_buf);
    free_state_list(threads_state);

    return ptnote_hdr_count;

proc_cleanup:
    free(nt_file_buf);
    free(auxv_buf);
    free_state_list(threads_state);

    return -1;
}

static ssize_t write_generic_note(const int fd, size_t* table_offset, size_t* data_offset, const void* buf, const size_t buf_sz, const int type, const char* name) {
    Elf64_Phdr phdr;
    ssize_t write_sz;

    write_sz = write_note_data(fd, data_offset, buf, buf_sz, type, name);
    if (write_sz < 0) {
        return -1;
    }

    create_program_header_ptnote(&phdr, (size_t) write_sz, data_offset);
    if (write_phdr_entry(fd, table_offset, &phdr) < 0) {
        return -1;
    }
    *data_offset += write_sz;


    return 1; /* 1 written note */
}

static ssize_t write_note_data(const int fd, const size_t* data_offset, const void* data, const size_t data_len, const int type, const char* name) {
    Elf64_Nhdr nhdr;
    size_t name_len;
    size_t name_len_padding;
    size_t data_len_padding;
    size_t note_sz;
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
        return -1;
    }

    if (writev(fd, iov, 5) != note_sz) {
        return -1;
    }

    return note_sz;
}

static ssize_t write_threads_state(const int fd, size_t* table_offset, size_t* data_offset, const thread_state_t* head) {
    const thread_state_t* entry;
    size_t note_sz;
    ssize_t written_hdr;

    written_hdr = 0;
    entry = head;

    while (entry) {
        Elf64_Phdr phdr;
        size_t tmp_data_offset;
        ssize_t write_sz;

        note_sz = 0;

        tmp_data_offset = *data_offset + note_sz;
        write_sz = write_note_data(fd, &tmp_data_offset, &entry->prstatus, sizeof(entry->prstatus), NT_PRSTATUS, "CORE");
        if (write_sz < 0) {
            return -1;
        }
        note_sz += write_sz;

        tmp_data_offset = *data_offset + note_sz;
        write_sz = write_note_data(fd, &tmp_data_offset, &entry->fpregs, sizeof(entry->fpregs), NT_FPREGSET, "CORE");
        if (write_sz < 0) {
            return -1;
        }
        note_sz += write_sz;

        tmp_data_offset = *data_offset + note_sz;
        write_sz = write_note_data(fd, &tmp_data_offset, &entry->pac_mask, sizeof(entry->pac_mask), NT_ARM_PAC_MASK, "LINUX");
        if (write_sz < 0) {
            return -1;
        }
        note_sz += write_sz;

        tmp_data_offset = *data_offset + note_sz;
        write_sz = write_note_data(fd, &tmp_data_offset, &entry->siginfo, sizeof(entry->siginfo), NT_SIGINFO, "CORE");
        if (write_sz < 0) {
            return -1;
        }
        note_sz += write_sz;

        create_program_header_ptnote(&phdr, note_sz, data_offset);
        if (write_phdr_entry(fd, table_offset, &phdr) < 0) {
            return -1;
        }
        *data_offset += note_sz;

        written_hdr++;

        entry = entry->next;
    }

    return written_hdr;
}

static int write_phdr_entry(const int fd, size_t* table_offset, const Elf64_Phdr* phdr) {
    if (lseek(fd, *table_offset, SEEK_SET) < 0) {
        return -1;
    }

    if (write(fd, phdr, sizeof(*phdr)) != sizeof(*phdr)) {
        return -1;
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

    if (strchr(entry->perms, 'r') && (entry->len ? strcmp(entry->pathname, "[vvar]") : 1)) {
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

static long get_pagesize(void) {
    long pagesize;

    pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize < 0) {
        return PAGE_SIZE_DEFAULT;
    }

    return pagesize;
}
