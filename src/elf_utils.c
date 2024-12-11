#include "elf_utils.h"
#include <stddef.h>
#include <elf.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "mem_reader.h"

#define PAGE_SIZE_DEFAULT 4096
#define PT_NOTE_ALIGNMENT 4

static ssize_t dump_process_memory(const int, const maps_entry_t*, const pid_t);
static ssize_t dump_process_info(const int, const maps_entry_t*, const pid_t);
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

    /*

    Elf64_Phdr phdr = create_program_header_ptnote(0);
    if (lseek(fd, table_offset, SEEK_SET) < 0) {
        return -1;
    };

    if (write(fd, &phdr, sizeof(Elf64_Phdr)) != sizeof(Elf64_Phdr)) {
        return -1;
    }

    */
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
    ssize_t ptnote_hdr_count;

    ptnote_hdr_count = 0;

    return ptnote_hdr_count;
}

static int write_phdr_entry(const int fd, const Elf64_Phdr* phdr) {
    if (lseek(fd, table_offset, SEEK_SET) < 0) {
        return -1;
    }

    if (write(fd, phdr, sizeof(Elf64_Phdr)) != sizeof(Elf64_Phdr)) {
        return -1;
    }

    table_offset += sizeof(Elf64_Phdr);

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
