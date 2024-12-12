#include "elf_utils.h"
#include <stddef.h>
#include <elf.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/procfs.h>
#include "proc_parser.h"

#define PAGE_SIZE_DEFAULT 4096
#define PT_NOTE_ALIGNMENT 4

#define PADDING4(x) (((x + PT_NOTE_ALIGNMENT - 1) & ~(PT_NOTE_ALIGNMENT - 1)) - x)

static ssize_t dump_process_memory(const int, const maps_entry_t*, const pid_t);
static ssize_t dump_process_info(const int, const maps_entry_t*, const pid_t);
static ssize_t write_nt_prpsinfo(const int, const prpsinfo_t*, const pid_t);
static Elf64_Phdr create_program_header_ptload(const maps_entry_t*);
static Elf64_Phdr create_program_header_ptnote(size_t);
static int write_phdr_entry(const int, const Elf64_Phdr*);
static long get_pagesize(void);

off_t table_offset;
off_t data_offset;

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
    elf_hdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
    elf_hdr.e_ident[EI_ABIVERSION] = 0;

    elf_hdr.e_type = ET_CORE;
    elf_hdr.e_machine = EM_X86_64;
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

    // Reserve space for ELF header
    table_offset = lseek(fd, sizeof(Elf64_Ehdr), SEEK_SET);
    if (table_offset < 0) {
        return -1;
    }

    data_offset = getpagesize();

    ptload_hdr_count = dump_process_memory(fd, head, pid);
    if (ptload_hdr_count < 0) {
        return -1;
    }

    ptnote_hdr_count = dump_process_info(fd, head, pid);
    if (ptnote_hdr_count < 0) {
        return -1;
    }

    // overflow
    return ptload_hdr_count + ptnote_hdr_count;
}

static ssize_t dump_process_memory(const int fd, const maps_entry_t* head, const pid_t pid) {
    const maps_entry_t* entry;
    ssize_t ptload_hdr_count;

    ptload_hdr_count = 0;
    entry = head;

    while (entry) {
        Elf64_Phdr phdr;

        phdr = create_program_header_ptload(entry);

        if (write_phdr_entry(fd, &phdr) < 0) {
            return -1;
        }

        if (dump_memory_region(fd, &phdr, pid) < 0) {
            return -1;
        }

        ptload_hdr_count++;
        entry = entry->next;
    }

    return ptload_hdr_count;
}

static ssize_t dump_process_info(const int fd, const maps_entry_t* head, const pid_t pid) {
    prpsinfo_t prpsinfo;
    ssize_t ptnote_hdr_count;
    int written_hdr;

    ptnote_hdr_count = 0;

    if (collect_nt_prpsinfo(pid, &prpsinfo) < 0) {
        return -1;
    }

    written_hdr = write_nt_prpsinfo(fd, &prpsinfo, pid);
    if (written_hdr < 0) {
        return -1;
    }
    ptnote_hdr_count += written_hdr;

    return ptnote_hdr_count;
}

static ssize_t write_nt_prpsinfo(const int fd, const prpsinfo_t* info, const pid_t pid) {
    Elf64_Phdr phdr;
    Elf64_Nhdr nhdr;
    size_t name_len;
    size_t data_len;
    size_t name_len_padding;
    size_t data_len_padding;
    size_t note_sz;
    ssize_t written_hdr;
    const char* note_name = "CORE";

    written_hdr = 0;

    name_len = strlen(note_name) + 1;
    data_len = sizeof(*info);

    name_len_padding = PADDING4(name_len);
    data_len_padding = PADDING4(data_len);

    note_sz = sizeof(nhdr) + name_len + name_len_padding + data_len + data_len_padding;
    phdr = create_program_header_ptnote(note_sz);

    if (write_phdr_entry(fd, &phdr) < 0) {
        return -1;
    }
    written_hdr++;

    nhdr.n_namesz = name_len;
    nhdr.n_descsz = data_len;
    nhdr.n_type = NT_PRPSINFO;

    if (lseek(fd, data_offset, SEEK_SET) < 0) {
        return -1;
    }

    if (write(fd, &nhdr, sizeof(nhdr)) != sizeof(nhdr)) {
        return -1;
    }

    if (write(fd, note_name, name_len) != name_len) {
        return -1;
    }

    if (name_len_padding) {
        char p_bytes[4] = {0};
        if (write(fd, p_bytes, name_len_padding) != name_len_padding) {
            return -1;
        }
    }

    if (write(fd, info, data_len) != data_len) {
        return -1;
    }

    if (data_len_padding) {
        char p_bytes[4] = {0};
        if (write(fd, p_bytes, data_len_padding) != data_len_padding) {
            return -1;
        }
    }

    data_offset += note_sz;

    return written_hdr;
}

static int write_phdr_entry(const int fd, const Elf64_Phdr* phdr) {
    if (lseek(fd, table_offset, SEEK_SET) < 0) {
        return -1;
    }

    if (write(fd, phdr, sizeof(*phdr)) != sizeof(*phdr)) {
        return -1;
    }

    table_offset += sizeof(*phdr);

    return 0;
}

static Elf64_Phdr create_program_header_ptload(const maps_entry_t* entry) {
    Elf64_Phdr phdr;
    memset(&phdr, 0, sizeof(Elf64_Phdr));

    phdr.p_type = PT_LOAD;
    phdr.p_vaddr = entry->start_addr;
    phdr.p_paddr = 0;
    phdr.p_filesz = entry->end_addr - entry->start_addr;
    phdr.p_memsz = phdr.p_filesz;

    if (strchr(entry->perms, 'r') && strcmp(entry->pathname, "[vvar]")) {
        phdr.p_flags |= PF_R;
    }
    if (strchr(entry->perms, 'w')) {
        phdr.p_flags |= PF_W;
    }
    if (strchr(entry->perms, 'x')) {
        phdr.p_flags |= PF_X;
    }

    phdr.p_align = get_pagesize();
    phdr.p_offset = data_offset;

    return phdr;
}

static Elf64_Phdr create_program_header_ptnote(size_t note_sz) {
    Elf64_Phdr phdr;
    memset(&phdr, 0, sizeof(Elf64_Phdr));

    phdr.p_type = PT_NOTE;
    phdr.p_vaddr = 0;
    phdr.p_paddr = 0;
    phdr.p_filesz = note_sz;
    phdr.p_memsz = 0;
    phdr.p_flags = 0;
    phdr.p_align = PT_NOTE_ALIGNMENT;
    phdr.p_offset = data_offset;

    return phdr;
}

static long get_pagesize(void) {
    long pagesize;

    pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize < 0) {
        return PAGE_SIZE_DEFAULT;
    }

    return pagesize;
}
