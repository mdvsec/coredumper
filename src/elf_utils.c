#include "elf_utils.h"
#include <stddef.h>
#include <elf.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "mem_reader.h"

#define PAGE_SIZE_DEFAULT 4096
#define PT_NOTE_ALIGNMENT 4

static Elf64_Phdr create_program_header_ptload(const maps_entry_t*);
static Elf64_Phdr create_program_header_ptnote(size_t);
static long get_pagesize(void);

static uint64_t current_coredump_offset;
extern size_t mem_region_count;

int write_elf_header(const int fd) {
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
    elf_hdr.e_phnum = mem_region_count + 1; // PT_NOTE added

    current_coredump_offset = get_pagesize();

    if (write(fd, &elf_hdr, sizeof(elf_hdr)) != sizeof(Elf64_Ehdr)) {
        return -1;
    }

    return 0;
}

int write_elf_program_headers(const int fd, const maps_entry_t* head, const pid_t pid) {
    const maps_entry_t* entry;
    off_t table_offset;

    table_offset = lseek(fd, 0, SEEK_CUR);
    if (table_offset < 0) {
        return -1;
    }

    entry = head;
    while (entry) {
        Elf64_Phdr phdr;

        phdr = create_program_header_ptload(entry);

        if (lseek(fd, table_offset, SEEK_SET) < 0) {
            return -1;
        };

        if (write(fd, &phdr, sizeof(Elf64_Phdr)) != sizeof(Elf64_Phdr)) {
            return -1;
        }

        table_offset += sizeof(Elf64_Phdr);

        if (lseek(fd, phdr.p_offset, SEEK_SET) < 0) {
            return -1;
        }

        if (dump_memory_region(&phdr, fd, pid) < 0) {
            return -1;
        }

        entry = entry->next;
    }

    Elf64_Phdr phdr = create_program_header_ptnote(0);
    if (lseek(fd, table_offset, SEEK_SET) < 0) {
        return -1;
    };

    if (write(fd, &phdr, sizeof(Elf64_Phdr)) != sizeof(Elf64_Phdr)) {
        return -1;
    }

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
    phdr.p_offset = current_coredump_offset;

    current_coredump_offset += phdr.p_memsz;
    current_coredump_offset = (current_coredump_offset + phdr.p_align - 1) & ~(phdr.p_align - 1);

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
    phdr.p_offset = current_coredump_offset;

    current_coredump_offset += phdr.p_filesz;
    current_coredump_offset = (current_coredump_offset + phdr.p_align - 1) & ~(phdr.p_align - 1);

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
